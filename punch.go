package main

// 打洞会话核心
//
// 协议极简（13 字节固定头）：
//   [0:4]  magic "P2P4"
//   [4]    类型  'P' = ping,  'Q' = pong
//   [5:13] 序列号 (大端 uint64)
//
// 为什么要 ping/pong 而不是"收到包就算成功"：
//   收到对方的包只证明【对方 -> 我】这一个方向通。
//   回一个 pong 并等对方对【我的 ping】回 pong，才能证明【我 -> 对方】也通。
//   两个方向都验证过，通道才算真的建立。

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

const (
	protoMagic = "P2P4"
	pktPing    = 'P'
	pktPong    = 'Q'
	pktHdrLen  = 13
)

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

// Run 主循环：读包 + 定时发包 + 保活。stop 关闭后返回。
func (s *Session) Run(stop <-chan struct{}, interval time.Duration) {
	seq := uint64(0)
	buf := make([]byte, 2048)
	lastSend := time.Time{}
	lastHold := time.Time{}

	for {
		select {
		case <-stop:
			return
		default:
		}

		// ---- 收 ----
		_ = s.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, from, err := s.conn.ReadFromUDP(buf)
		if err == nil && n > 0 {
			s.handlePacket(buf[:n], from)
		}

		now := time.Now()

		// ---- 发 ----
		s.mu.Lock()
		peer := s.peer
		hold := s.holdTarget
		s.mu.Unlock()

		if peer != nil {
			if now.Sub(lastSend) >= interval {
				seq++
				pkt := buildPacket(pktPing, seq)
				s.mu.Lock()
				s.pending[seq] = now
				s.sent++
				// 清理过老的 pending 记录，防止无限增长
				for k, t := range s.pending {
					if now.Sub(t) > 30*time.Second {
						delete(s.pending, k)
					}
				}
				s.mu.Unlock()
				_, _ = s.conn.WriteToUDP(pkt, peer)
				lastSend = now
			}
		} else if hold != nil {
			// 还没有对方的地址，但要保住 NAT 映射 —— 向 STUN 服务器发保活
			if now.Sub(lastHold) >= 15*time.Second {
				req := buildBindingRequest()
				_, _ = s.conn.WriteToUDP(req.packet, hold)
				lastHold = now
			}
		}
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
