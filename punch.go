package main

// 打洞会话核心
//
// 协议极简（13 字节固定头）：
//   [0:4]  magic "*P2P"
//   [4]    类型  'P' = ping,  'Q' = pong
//   [5:13] 序列号 (大端 uint64)
//
// 魔数为什么是 "*P2P" 而不是更好看的 "P2P4"：
//   开了数据面之后，这个 socket 归 quic-go 管，我们自己的包要从
//   Transport.ReadNonQUICPacket 那里取回来。它的判定规则是
//   【首字节的 bit7 和 bit6 都为 0】。而 ASCII 可打印字符（0x20~0x7E）
//   的 0x40 位必然是 1，全都会被当成 QUIC 短包头 —— quic-go 拿着它去查
//   连接 ID，查不到，于是回一个 stateless reset，反过来打断我们的心跳。
//   所以首字节必须落在 0x00~0x3F，这里取 0x2A('*')。
//   好处是分类变成确定性的：QUIC 包头必然带 0x40 或 0x80，永远撞不上。
//
// 为什么要 ping/pong 而不是"收到包就算成功"：
//   收到对方的包只证明【对方 -> 我】这一个方向通。
//   回一个 pong 并等对方对【我的 ping】回 pong，才能证明【我 -> 对方】也通。
//   两个方向都验证过，通道才算真的建立。

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	protoMagic = "*P2P"
	pktPing    = 'P'
	pktPong    = 'Q'
	pktHdrLen  = 13
)

// packetSource 抽象「从哪儿读我们自己协议的包」。
//
// 没开数据面时直接读 socket；开了数据面后 socket 归 quic-go 管，
// 我们的包得从 Transport.ReadNonQUICPacket 取。
// 把这个差异收在一个接口里，会话主循环就只有一份。
type packetSource interface {
	ReadPacket(ctx context.Context, b []byte) (int, *net.UDPAddr, error)
}

// directSource 直接读 socket（未启用数据面）
type directSource struct{ conn *net.UDPConn }

func (d directSource) ReadPacket(ctx context.Context, b []byte) (int, *net.UDPAddr, error) {
	// 用短读超时轮询，这样 ctx 取消后能及时退出（否则会一直阻塞在 Read 上）
	_ = d.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	n, from, err := d.conn.ReadFromUDP(b)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return 0, nil, nil // 读超时不是错误
		}
		return 0, nil, err
	}
	return n, from, nil
}

// nonQUICSource 从 quic-go 那里取「不像 QUIC 的包」
type nonQUICSource struct{ t *quic.Transport }

func (s nonQUICSource) ReadPacket(ctx context.Context, b []byte) (int, *net.UDPAddr, error) {
	n, addr, err := s.t.ReadNonQUICPacket(ctx, b)
	if err != nil {
		return 0, nil, err
	}
	a, _ := addr.(*net.UDPAddr)
	return n, a, nil
}

func buildPacket(t byte, seq uint64) []byte {
	b := make([]byte, pktHdrLen)
	copy(b[0:4], protoMagic)
	b[4] = t
	binary.BigEndian.PutUint64(b[5:13], seq)
	return b
}

func parsePacket(b []byte) (byte, uint64, bool) {
	if len(b) < pktHdrLen || string(b[0:4]) != protoMagic {
		return 0, 0, false
	}
	return b[4], binary.BigEndian.Uint64(b[5:13]), true
}

// SessionStats 会话统计快照
type SessionStats struct {
	Sent     int
	Received int
	Pongs    int
	Foreign  int
	Peer     string
	PeerSeen bool
	RTTMin   time.Duration
	RTTAvg   time.Duration
	RTTMax   time.Duration
	Elapsed  time.Duration
	LastRecv time.Duration // 距上次收到对方包的时长；-1 表示从未收到
}

// Session 一次打洞会话
type Session struct {
	conn *net.UDPConn

	mu         sync.Mutex
	peer       *net.UDPAddr // 已知的对方地址（可能由用户手工输入，或从收到的包自动学到）
	lastFrom   *net.UDPAddr // 最近一次真正收到对方包的来源地址
	holdTarget *net.UDPAddr // 还没有 peer 时，用它保活（就是给我们提供映射的那台 STUN 服务器）
	peerSeen   bool
	sent       int
	received   int
	pongs      int
	foreign    int
	rtts       []time.Duration
	pending    map[uint64]time.Time
	startedAt  time.Time
	lastRecv   time.Time

	// 这两个只在发包循环里用，不需要锁
	seq      uint64
	lastHold time.Time
}

func NewSession(conn *net.UDPConn) *Session {
	return &Session{
		conn:      conn,
		pending:   map[uint64]time.Time{},
		startedAt: time.Now(),
	}
}

func (s *Session) SetPeer(a *net.UDPAddr) {
	s.mu.Lock()
	s.peer = a
	s.mu.Unlock()
}

func (s *Session) SetHoldTarget(a *net.UDPAddr) {
	s.mu.Lock()
	s.holdTarget = a
	s.mu.Unlock()
}

func (s *Session) Peer() *net.UDPAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peer
}

// LastFrom 最近一次真正收到对方包的来源地址。
//
// 这比「用户粘贴过来的地址」更可靠：NAT 可能给对方分配了一个和它自己
// 看到的【不同】的出口端口，只有实际收到的包才能证明哪个地址真的通。
// 数据面要往对方拨 QUIC，用这个地址成功率更高。
func (s *Session) LastFrom() *net.UDPAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastFrom
}

// PeerSeen 是否已经收到过对方的任何本协议包
func (s *Session) PeerSeen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerSeen
}

// Verified 双向都验证过了（收到过至少一个 pong）
func (s *Session) Verified() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pongs > 0
}

func (s *Session) Stats() SessionStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := SessionStats{
		Sent: s.sent, Received: s.received, Pongs: s.pongs,
		Foreign: s.foreign, PeerSeen: s.peerSeen,
		Elapsed: time.Since(s.startedAt), LastRecv: -1,
	}
	if s.peer != nil {
		st.Peer = s.peer.String()
	}
	if len(s.rtts) > 0 {
		min, max, sum := s.rtts[0], s.rtts[0], time.Duration(0)
		for _, d := range s.rtts {
			if d < min {
				min = d
			}
			if d > max {
				max = d
			}
			sum += d
		}
		st.RTTMin, st.RTTMax = min, max
		st.RTTAvg = sum / time.Duration(len(s.rtts))
	}
	if !s.lastRecv.IsZero() {
		st.LastRecv = time.Since(s.lastRecv)
	}
	return st
}

// Run 跑会话：一个收包循环 + 一个定时发包循环，ctx 取消后返回。
func (s *Session) Run(ctx context.Context, interval time.Duration, src packetSource) {
	go func() {
		buf := make([]byte, 2048)
		for {
			if ctx.Err() != nil {
				return
			}
			n, from, err := src.ReadPacket(ctx, buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if n > 0 && from != nil {
				s.handlePacket(buf[:n], from)
			}
		}
	}()

	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			s.tick(now)
		}
	}
}

// tick 一次发包。有了对方地址就发 ping；没有就先向 STUN 服务器保活。
func (s *Session) tick(now time.Time) {
	s.mu.Lock()
	peer := s.peer
	hold := s.holdTarget
	s.mu.Unlock()

	if peer != nil {
		s.seq++
		pkt := buildPacket(pktPing, s.seq)
		s.mu.Lock()
		s.pending[s.seq] = now
		s.sent++
		// 清理过老的 pending 记录，防止无限增长
		for k, t := range s.pending {
			if now.Sub(t) > 30*time.Second {
				delete(s.pending, k)
			}
		}
		s.mu.Unlock()
		_, _ = s.conn.WriteToUDP(pkt, peer)
		return
	}

	// 还没有对方的地址，但要保住 NAT 映射 —— 向 STUN 服务器发保活。
	// 映射 30 秒~5 分钟就会过期，而人工传递地址是要花时间的。
	if hold != nil && now.Sub(s.lastHold) >= 15*time.Second {
		s.lastHold = now
		_, _ = s.conn.WriteToUDP(buildBindingRequest().packet, hold)
	}
}

func (s *Session) handlePacket(b []byte, from *net.UDPAddr) {
	typ, sq, ok := parsePacket(b)
	if !ok {
		// 收到不认识的包：记录下来。这通常意味着打洞其实已经成功，
		// 只是对方跑的是别的程序（比如被用户手工接上了）。
		s.mu.Lock()
		s.foreign++
		s.lastRecv = time.Now()
		s.mu.Unlock()
		return
	}

	s.mu.Lock()
	s.received++
	s.peerSeen = true
	s.lastRecv = time.Now()
	s.lastFrom = from
	if s.peer == nil {
		// 全锥形 NAT 的情况下，对方的包能直接到达 —— 自动学到地址
		s.peer = from
	}
	s.mu.Unlock()

	switch typ {
	case pktPing:
		_, _ = s.conn.WriteToUDP(buildPacket(pktPong, sq), from)
	case pktPong:
		s.mu.Lock()
		if t, ok := s.pending[sq]; ok {
			s.rtts = append(s.rtts, time.Since(t))
			s.pongs++
			delete(s.pending, sq)
		}
		s.mu.Unlock()
	}
}
