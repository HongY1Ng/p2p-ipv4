package main

// 数据面：把打洞打通的那条 UDP 路径，变成能跑 TCP 的通道
//
// ── 核心约束（整个实现里最容易踩的坑）────────────────────────────
// 打洞打通的是「【某个本地 UDP 端口】↔【某个 NAT 映射】」这一条路。
// 如果 QUIC 自己再开一个 UDP socket，它会拿到一个【全新的、没被打通的】
// NAT 映射，照样被 NAT 挡在外面 —— 等于白打一次洞。
// 所以 QUIC 必须复用那个已经打通的 socket。
//
// 复用方式不是自己写解复用循环，而是用 quic-go 自带的 Non-QUIC 包通道：
// Transport.ReadNonQUICPacket 会把「不像 QUIC 的包」交还给我们，判定规则
// 是首字节的 bit7/bit6 都为 0。我们的魔数 "*P2P" 首字节 0x2A 满足，而任何
// QUIC 包头必然带 0x40 或 0x80，所以这个分类是确定性的、不会误判。
//
// 好处是把原始 *net.UDPConn 整个交给 Transport，从而保留 GSO/GRO、ECN
// 读取和 DF 位 —— 其中 DF 是 DPLPMTUD（路径 MTU 发现）的前提，自己包一层
// PacketConn 会把这些全丢掉，在低 MTU 的链路上明显掉速。
//
// ── 为什么是 QUIC 而不是自己撸一个可靠 UDP ───────────────────────
// 在 UDP 上承载 TCP 有个经典陷阱叫 TCP meltdown：外层丢包被内层 TCP 误判成
// 拥塞，两端窗口一起塌陷，吞吐断崖式下跌。要绕开它必须实现正经的拥塞控制、
// 丢包恢复、RTT 估计。这些正是 QUIC 解决的问题，自己写只会写得更差。

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// streamMagic 每条流转发的开头 4 字节，用来确认对方跑的是同一个协议
	streamMagic = "FWD1"

	// errCodeAbort 我们自己定义的 QUIC 流错误码，表示「本地这一侧断了」
	errCodeAbort quic.StreamErrorCode = 0x1f
)

// fwdRule 一条本地转发规则：本地监听 localPort，转发到【对方】的 remotePort
type fwdRule struct {
	localPort  uint16
	remotePort uint16
}

// shareRule 一条开放规则：对方请求 key 端口时，实际去连 target
type shareRule struct {
	key    uint16
	target string
}

// fwdOptions 数据面的全部配置
type fwdOptions struct {
	token    string
	shares   map[uint16]shareRule
	forwards []fwdRule
	bindHost string
}

// dataPlane 数据面：一条已经打通的 socket + 跑在它上面的 QUIC
type dataPlane struct {
	conn      *net.UDPConn
	transport *quic.Transport
	opts      fwdOptions

	peer atomic.Pointer[net.UDPAddr] // 对方地址（打洞成功后才知道）

	mu    sync.Mutex
	qconn *quic.Conn // 出站 QUIC 连接，懒建 + 断了自动重连

	active atomic.Int64 // 当前并发转发数
	up     atomic.Int64 // 累计上行字节
	down   atomic.Int64 // 累计下行字节
}

func newDataPlane(conn *net.UDPConn, opts fwdOptions) *dataPlane {
	// ⚠️ 交出去之前必须先清掉 socket 上残留的读/写超时。
	//
	// ProbeNAT 用同一个 socket 反复查 STUN，最后一次设的读超时（此时已经
	// 过期）会留在 socket 上。一旦交给 Transport，它的读循环每次 ReadFrom
	// 都立刻拿到超时错误，然后走 Temporary() 分支 continue —— 结果是读
	// 循环空转、socket 再也【没有被真正读过】，一个包都收不到。
	//
	// 这个坑极其隐蔽：打洞阶段完全正常，一接上数据面心跳就全断，
	// 而且两端现象一模一样，很容易误判成 NAT 或防火墙问题。
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Time{})

	return &dataPlane{
		conn: conn,
		// 把已经打通的 socket 整个交给 quic-go。
		// 从这里开始，我们自己【不能再直接读这个 conn】——
		// 我们的包要走 Transport.ReadNonQUICPacket。
		transport: &quic.Transport{Conn: conn},
		opts:      opts,
	}
}

func (d *dataPlane) enabled() bool {
	return len(d.opts.shares) > 0 || len(d.opts.forwards) > 0
}

// reader 返回打洞会话应该用的收包源
func (d *dataPlane) reader() packetSource { return nonQUICSource{d.transport} }

// start 在打洞【之前】调用，先把 QUIC 监听挂上。
// 顺序很重要：如果等打洞成功了再挂，对方的握手可能比我们早到，
// 那时包会因为「没有对应的 listener」被丢掉（QUIC 会重传，但白等几个 RTT）。
func (d *dataPlane) start(ctx context.Context) error {
	if len(d.opts.shares) == 0 {
		return nil
	}
	tlsConf, err := serverTLSConfig(d.opts.token)
	if err != nil {
		return err
	}
	ln, err := d.transport.Listen(tlsConf, quicConfig())
	if err != nil {
		return fmt.Errorf("QUIC 监听失败: %w", err)
	}
	go d.acceptLoop(ctx, ln)
	return nil
}

// attach 在打洞【成功之后】调用：这时才知道对方地址，可以开始建出站连接了。
func (d *dataPlane) attach(ctx context.Context, peer *net.UDPAddr) error {
	if peer == nil {
		return errors.New("还没拿到对方地址")
	}
	d.peer.Store(peer)

	if len(d.opts.forwards) == 0 {
		return nil
	}

	for _, r := range d.opts.forwards {
		addr := net.JoinHostPort(d.opts.bindHost, strconv.Itoa(int(r.localPort)))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("本地监听 %s 失败: %w", addr, err)
		}
		okf("本地转发: %s  →  对方的 %d 端口", addr, r.remotePort)
		go d.acceptLocal(ctx, ln, r)
	}

	go d.maintain(ctx)
	return nil
}

// describe 给状态显示用的一行摘要
func (d *dataPlane) describe() string {
	var parts []string
	for _, r := range d.opts.forwards {
		parts = append(parts, fmt.Sprintf("→对方%d", r.remotePort))
	}
	for k := range d.opts.shares {
		parts = append(parts, fmt.Sprintf("开放%d", k))
	}
	return strings.Join(parts, " ")
}

func (d *dataPlane) stats() (active, up, down int64) {
	return d.active.Load(), d.up.Load(), d.down.Load()
}

// ---------- 配置 ----------

func quicConfig() *quic.Config {
	return &quic.Config{
		// 比常见的 NAT 映射超时（30s~5min）短，靠 KeepAlive 撑住映射。
		// 注意打洞心跳本来也在保活，这里是双保险。
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 15 * time.Second,

		MaxIncomingStreams: 256,

		// 远程桌面是「高延迟 + 突发」的流量。窗口按 BDP 给足：
		// 太小会把吞吐直接卡死在窗口上，表现就是「能动但很糊」。
		InitialStreamReceiveWindow:     512 * 1024,
		MaxStreamReceiveWindow:         6 * 1024 * 1024,
		InitialConnectionReceiveWindow: 1 * 1024 * 1024,
		MaxConnectionReceiveWindow:     16 * 1024 * 1024,
	}
}

// ---------- 服务端：接受对方的转发请求 ----------

func (d *dataPlane) acceptLoop(ctx context.Context, ln *quic.Listener) {
	for {
		c, err := ln.Accept(ctx)
		if err != nil {
			// ctx 取消、或 listener 被关，都属于正常退出
			return
		}
		okf("数据面: 对方已连入 (%s)", c.RemoteAddr())
		go d.serveConn(ctx, c)
	}
}

func (d *dataPlane) serveConn(ctx context.Context, c *quic.Conn) {
	for {
		st, err := c.AcceptStream(ctx)
		if err != nil {
			return
		}
		go d.serveStream(st)
	}
}

// serveStream 处理对方开过来的一条流：读 6 字节头 -> 查白名单 -> 连本地 TCP
func (d *dataPlane) serveStream(st *quic.Stream) {
	defer st.CancelRead(errCodeAbort)

	hdr := make([]byte, 6)
	_ = st.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(st, hdr); err != nil {
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	if string(hdr[0:4]) != streamMagic {
		warn("数据面: 收到不认识的开头，丢弃该流")
		return
	}
	port := binary.BigEndian.Uint16(hdr[4:6])

	rule, ok := d.opts.shares[port]
	if !ok {
		// 默认拒绝。--share 是白名单，不是「随便连我本机」。
		warn("数据面: 对方请求了没有开放的端口 %d，已拒绝", port)
		return
	}

	tcp, err := net.DialTimeout("tcp", rule.target, 10*time.Second)
	if err != nil {
		warn("数据面: 连 %s 失败: %v", rule.target, err)
		return
	}
	okf("数据面: 对方 → %s", rule.target)
	d.bridge(st, tcp)
}

// ---------- 客户端：把本地 TCP 连接转发到对方 ----------

func (d *dataPlane) acceptLocal(ctx context.Context, ln net.Listener, r fwdRule) {
	for {
		tcp, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go d.forwardToPeer(ctx, tcp, r)
	}
}

func (d *dataPlane) forwardToPeer(ctx context.Context, tcp net.Conn, r fwdRule) {
	defer tcp.Close()

	c, err := d.getConn(ctx)
	if err != nil {
		warn("数据面: 连不上对方: %v", err)
		return
	}
	st, err := c.OpenStreamSync(ctx)
	if err != nil {
		warn("数据面: 打开 QUIC 流失败: %v", err)
		return
	}

	hdr := make([]byte, 6)
	copy(hdr, streamMagic)
	binary.BigEndian.PutUint16(hdr[4:6], r.remotePort)
	if _, err := st.Write(hdr); err != nil {
		st.CancelWrite(errCodeAbort)
		return
	}

	d.bridge(st, tcp)
}

// getConn 取出站的 QUIC 连接，没有（或已断）就现建一个。
// 整个函数持锁，避免并发触发多次握手 —— 后到的调用者等锁，
// 拿到锁时连接已经建好，直接复用。
func (d *dataPlane) getConn(ctx context.Context) (*quic.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if c := d.qconn; c != nil && c.Context().Err() == nil {
		return c, nil
	}

	peer := d.peer.Load()
	if peer == nil {
		return nil, errors.New("还不知道对方地址")
	}
	tlsConf, err := clientTLSConfig(d.opts.token)
	if err != nil {
		return nil, err
	}

	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c, err := d.transport.Dial(dctx, peer, tlsConf, quicConfig())
	if err != nil {
		d.qconn = nil
		return nil, err
	}
	d.qconn = c
	return c, nil
}

// maintain 守着 QUIC 连接：断了就以指数退避重连。
// 打洞那条路本身是活的（有心跳），但中间任何一段 NAT 都可能把
// QUIC 的闲置连接清掉，所以不能只连一次就完事。
func (d *dataPlane) maintain(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		c, err := d.getConn(ctx)
		if err != nil {
			warn("数据面: 建立 QUIC 连接失败（%v），%v 后重试", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		okf("数据面: 已连上对方 (%s)", c.RemoteAddr())

		select {
		case <-ctx.Done():
			return
		case <-c.Context().Done():
		}
		// 连接断了，清掉让下一轮重建
		d.mu.Lock()
		if d.qconn == c {
			d.qconn = nil
		}
		d.mu.Unlock()
	}
}

// ---------- 双向管道 ----------

// bridge 把一条 QUIC 流和一个本地 TCP 连接对接起来。
//
// 关键点：两边都要支持【半关闭】。TCP 的 FIN 要转成 QUIC 的 FIN
// （Stream.Close 只关发送方向），否则像 RDP、HTTP 这种「客户端发完请求
// 就关写、但还要继续收响应」的协议会直接卡死。
func (d *dataPlane) bridge(st *quic.Stream, tcp net.Conn) {
	d.active.Add(1)
	defer d.active.Add(-1)
	defer tcp.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// 本地 TCP → 对方
	go func() {
		defer wg.Done()
		n, err := io.Copy(st, tcp)
		d.up.Add(n)
		if err != nil {
			st.CancelWrite(errCodeAbort)
			return
		}
		_ = st.Close() // 关发送方向 = 发 FIN，读方向仍然开着
	}()

	// 对方 → 本地 TCP
	go func() {
		defer wg.Done()
		n, err := io.Copy(tcp, st)
		d.down.Add(n)
		_ = err
		if c, ok := tcp.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}()

	wg.Wait()
	st.CancelRead(errCodeAbort)
}

// ---------- 参数解析 ----------

// parseShare 解析 --share 的值：
//
//	3389                    开放本机的 127.0.0.1:3389
//	3389=192.168.1.5:3389   开放内网另一台机器的 3389
//
// 左边的端口号是【对方要请求的编号】，右边的才是真正去连的地址。
func parseShare(s string) (shareRule, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return shareRule{}, errors.New("空值")
	}
	key, target := s, ""
	if i := strings.IndexByte(s, '='); i >= 0 {
		key, target = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}
	p, err := strconv.ParseUint(key, 10, 16)
	if err != nil || p == 0 {
		return shareRule{}, fmt.Errorf("端口号不对: %q", key)
	}
	if target == "" {
		target = net.JoinHostPort("127.0.0.1", strconv.FormatUint(p, 10))
	} else if _, _, err := net.SplitHostPort(target); err != nil {
		return shareRule{}, fmt.Errorf("目标地址不对: %q（应该像 192.168.1.5:3389）", target)
	}
	return shareRule{key: uint16(p), target: target}, nil
}

// parseForward 解析 --forward 的值：
//
//	13389:3389   本地监听 127.0.0.1:13389，连上来的流量发给【对方】的 3389
func parseForward(s string) (fwdRule, error) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return fwdRule{}, fmt.Errorf("格式应为 本地端口:对方端口，比如 13389:3389")
	}
	l, err1 := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	r, err2 := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
	if err1 != nil || err2 != nil || l == 0 || r == 0 {
		return fwdRule{}, fmt.Errorf("端口号不对: %q", s)
	}
	return fwdRule{localPort: uint16(l), remotePort: uint16(r)}, nil
}

// randomToken 生成一个 16 位十六进制的共享密钥，方便口头/聊天传递。
func randomToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// 熵源坏了也不能 panic：退回时间戳，安全性下降但工具还能用
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b)
}
