package main

// advertise / connect 两个子命令的实现
//
// 为什么不是"单向报地址就够了"：
//   打洞 = 双方各自先向对方发包，在【各自的】NAT 上建立"允许对方回包"的规则。
//   只建立一边的规则，另一边照样丢包。
//   所以本工具的策略是：
//     1) advertise 先只广播 + 保活 + 静听
//     2) 如果对方能直接打进来（你的 NAT 是全锥形）-> 自动学到地址，一步到位
//     3) 打不进来 -> 提示你粘贴对方地址 -> 双向同时打洞
//
// 打洞成功之后，如果指定了 --share / --forward，就在这条路径上起 QUIC 数据面，
// 把 TCP 端口转发跑起来（详见 forward.go）。

import (
	"context"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"
)

func cmdAdvertise(args []string) int { return runPunch("advertise", args) }
func cmdConnect(args []string) int   { return runPunch("connect", args) }

func runPunch(mode string, args []string) int {
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	port := fs.Int("port", DefaultPort, "本地 UDP 端口（两端必须一致）")
	hold := fs.Bool("hold", true, "成功后保持通道存活（Ctrl+C 退出）")
	var totalTO, punchWindow, promptAfter, stunTO time.Duration
	newSecsFlag(fs, &totalTO, "timeout", 300*time.Second, "总超时（默认 300 秒）")
	newSecsFlag(fs, &punchWindow, "wait", 60*time.Second, "知道对方地址后，打洞尝试多久算失败（默认 60 秒）")
	newSecsFlag(fs, &promptAfter, "prompt", 20*time.Second, "多久没收到对方的包就提示粘贴对方地址（默认 20 秒）")
	newSecsFlag(fs, &stunTO, "stun-timeout", 3*time.Second, "每个 STUN 服务器的超时（默认 3 秒）")
	noHold := fs.Bool("no-hold", false, "成功后直接退出，不保持通道")

	var shareVals, forwardVals []string
	newListFlag(fs, &shareVals, "share",
		"开放本地 TCP 端口给对方（如 --share 3389，或 --share 3389=192.168.1.5:3389）")
	newListFlag(fs, &forwardVals, "forward",
		"把本地端口转发到「对方」的端口（如 --forward 13389:3389）")
	token := fs.String("token", "",
		"数据面共享密钥，两端必须一致；只开 --share 时会自动生成并打印")
	bindHost := fs.String("bind", "127.0.0.1", "转发监听的绑定地址（默认只监听本机）")
	_ = fs.Parse(reorderArgs(args))
	if *noHold {
		*hold = false
	}

	var peerArg string
	if mode == "connect" {
		if fs.NArg() < 1 {
			errf("用法: %s connect <对方IP:端口>", appName)
			return 2
		}
		peerArg = fs.Arg(0)
	}

	// ---- 数据面选项 ----
	shares := map[uint16]shareRule{}
	for _, v := range shareVals {
		r, err := parseShare(v)
		if err != nil {
			errf("--share %s: %v", v, err)
			return 2
		}
		if _, dup := shares[r.key]; dup {
			warn("--share %d 重复，以最后一个为准", r.key)
		}
		shares[r.key] = r
	}
	var forwards []fwdRule
	for _, v := range forwardVals {
		r, err := parseForward(v)
		if err != nil {
			errf("--forward %s: %v", v, err)
			return 2
		}
		forwards = append(forwards, r)
	}

	wantPlane := len(shares) > 0 || len(forwards) > 0
	tok := strings.TrimSpace(*token)
	tokenGenerated := false
	if wantPlane && tok == "" {
		if len(shares) > 0 {
			// 开放端口这一侧负责生成密钥，对方抄过去即可
			tok = randomToken()
			tokenGenerated = true
		} else {
			errf("--forward 需要 --token：填对方 advertise 时打印出来的那个密钥。")
			plain("    没有这个密钥就没法确认对端身份，等于把转发端口开给任何猜到你地址的人。")
			return 2
		}
	}

	conn, actual, err := listenUDP(*port)
	if err != nil {
		errf("无法绑定 UDP 端口: %v", err)
		return 1
	}
	defer conn.Close()

	banner(strings.ToUpper(mode), fmt.Sprintf("本地 UDP 端口: %d", actual))

	// ---- 1) 探测：顺便拿到我们自己的公网映射 ----
	// 注意：这一步必须直接读 socket。开了数据面之后 socket 归 quic-go 管，
	// 就再也不能直接 ReadFromUDP 了，所以 Transport 要在探测【之后】才建。
	info("正在探测 NAT 类型 ...")
	res := ProbeNAT(conn, stunTO, func(string, ...any) {})
	myIP, myPort, stunAddr, found := bestMapping(res)
	if !found {
		errf("无法从任何 STUN 服务器获得公网映射 —— 出站 UDP 可能被封。")
		printProbeReport(res)
		return 1
	}
	okf("NAT 类型: %s", res.Kind)
	if !res.Kind.Friendly() {
		warn("你的 NAT 不是锥形 —— 打洞成功率会很低。")
	}
	if res.HasIPv6 {
		warn("本机有公网 IPv6。如果对方也有，直接用 IPv6 直连会比打洞可靠得多。")
	}

	// ---- 2) 亮出自己的地址（和密钥）----
	myAddr := fmt.Sprintf("%s:%d", myIP.String(), myPort)
	if mode == "advertise" {
		highlight("把这行发给对方：", myAddr)
	} else {
		highlight("把这行发回给对方（如果对方需要）：", myAddr)
	}
	if tokenGenerated {
		highlight("数据面密钥也发过去：", tok)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ---- 3) 建数据面（如果要用）----
	var dp *dataPlane
	var src packetSource = directSource{conn}
	if wantPlane {
		dp = newDataPlane(conn, fwdOptions{
			token:    tok,
			shares:   shares,
			forwards: forwards,
			bindHost: *bindHost,
		})
		// 先挂上 QUIC 监听，免得对方的握手比我们早到
		if err := dp.start(ctx); err != nil {
			errf("数据面启动失败: %v", err)
			return 1
		}
		src = dp.reader()
	}

	// ---- 4) 建会话 ----
	sess := NewSession(conn)
	sess.SetHoldTarget(stunAddr) // 还没有对方地址时，靠它把 NAT 映射撑住

	if peerArg != "" {
		a, err := net.ResolveUDPAddr("udp4", peerArg)
		if err != nil || a.IP == nil {
			errf("对方地址格式不对: %s（应该像 1.2.3.4:56789）", peerArg)
			return 2
		}
		sess.SetPeer(a)
		okf("对方地址: %s", a)
	} else {
		info("等待对方连接（最多 %v）...", totalTO)
	}

	go sess.Run(ctx, 200*time.Millisecond, src)
	go readStdinPeer(sess, ctx.Done())

	// ---- 5) 等待通道建立 ----
	started := time.Now()
	overall := started.Add(totalTO)
	var punchDeadline time.Time
	prompted := false
	lastStatus := time.Time{}
	statusEvery := 500 * time.Millisecond
	if !stdoutIsTTY {
		statusEvery = 5 * time.Second
	}

	for {
		st := sess.Stats()

		if sess.Verified() {
			clearStatusLine()
			printSuccess(sess, dp)
			if dp != nil {
				peer := sess.LastFrom()
				if peer == nil {
					peer = sess.Peer()
				}
				if err := dp.attach(ctx, peer); err != nil {
					errf("数据面启动失败: %v", err)
					return 1
				}
			}
			if *hold {
				// 注意：这里【不能】取消 ctx —— 会话要继续发心跳，
				// 否则 NAT 映射会过期，而且状态显示会变成冻住的数字。
				holdChannel(sess, dp)
			}
			return 0
		}

		now := time.Now()
		if now.After(overall) {
			clearStatusLine()
			printFailure(sess, fmt.Sprintf("总超时 %v", totalTO), sess.Peer() != nil)
			return 1
		}

		p := sess.Peer()
		if p != nil && punchDeadline.IsZero() {
			punchDeadline = now.Add(punchWindow)
		}
		if !punchDeadline.IsZero() && now.After(punchDeadline) {
			clearStatusLine()
			if st.Received == 0 {
				printFailure(sess, fmt.Sprintf("尝试 %v，没有收到对方的任何数据包", punchWindow), true)
			} else {
				printFailure(sess, "收到过对方的包但握手未完成（可能单向不通）", true)
			}
			return 1
		}

		// advertise 模式：迟迟等不到人 -> 提示粘贴对方地址（双向交换）
		if mode == "advertise" && !prompted && p == nil && !sess.PeerSeen() &&
			now.Sub(started) > promptAfter {
			prompted = true
			clearStatusLine()
			warn("已经 %v 没收到对方的任何数据包。", promptAfter)
			plain("    这通常说明你的 NAT 不是「全锥形」，对方没法单向打进你的端口。")
			plain("    请让对方跑 'p2p connect <你上面那个地址>'，")
			plain("    然后把他屏幕上显示的地址粘贴到下面（双向同时打洞）：")
			fmt.Print("\n    > ")
			lastStatus = time.Time{}
		}

		// 单行状态刷新
		if now.Sub(lastStatus) > statusEvery {
			suffix := "  等待对方地址"
			if p != nil {
				suffix = "  打洞中"
			}
			statusLine("  已发出 %d / 收到 %d / 往返确认 %d   (%ds)%s",
				st.Sent, st.Received, st.Pongs, int(now.Sub(started).Seconds()), suffix)
			lastStatus = now
		}

		time.Sleep(200 * time.Millisecond)
	}
}

// holdChannel 成功后保持通道，持续显示延迟、丢包和转发统计
func holdChannel(sess *Session, dp *dataPlane) {
	if dp != nil && dp.enabled() {
		info("保持通道中（%s；每 5 秒刷新状态，Ctrl+C 退出）...", dp.describe())
	} else {
		info("保持通道中（每 5 秒刷新一次状态，Ctrl+C 退出）...")
	}
	fmt.Println()

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	last := sess.Stats()
	for range tick.C {
		st := sess.Stats()
		delta := st.Received - last.Received
		loss := "0%"
		if st.Sent > 0 {
			lossPct := 100.0 * float64(st.Sent-st.Pongs) / float64(st.Sent)
			if lossPct < 0 {
				lossPct = 0
			}
			loss = fmt.Sprintf("%.0f%%", lossPct)
		}
		line := fmt.Sprintf("  [%s] RTT %-8s  本周期收到 %d 包  累计往返 %d  估算丢包 %s",
			time.Now().Format("15:04:05"), fmtDur(st.RTTAvg), delta, st.Pongs, loss)
		if dp != nil && dp.enabled() {
			active, up, down := dp.stats()
			line += fmt.Sprintf("  │ 转发中 %d  上行 %s  下行 %s",
				active, humanBytes(up), humanBytes(down))
		}
		plain("%s", line)
		last = st
	}
}

// readStdinPeer 后台读 stdin：用户粘贴对方地址时写入会话。
// 必须在 ctx 取消时立刻退出，否则它会一直占用 stdin，
// 把后面交互式菜单的输入吃掉。
func readStdinPeer(sess *Session, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case raw, ok := <-stdinLines:
			if !ok {
				return
			}
			line := strings.TrimSpace(raw)
			if line == "" {
				continue
			}
			line = strings.TrimPrefix(strings.TrimSuffix(line, "]"), "[")
			a, err := net.ResolveUDPAddr("udp4", line)
			if err != nil || a.IP == nil || a.Port == 0 {
				clearStatusLine()
				warn("地址格式不对: %q  （应该像 1.2.3.4:56789）", line)
				fmt.Print("    > ")
				continue
			}
			a.IP = a.IP.To4()
			sess.SetPeer(a)
			clearStatusLine()
			okf("收到对方地址: %s，开始双向打洞", a)
		}
	}
}

// bestMapping 从探测结果里挑一个可用的映射，并返回对应 STUN 服务器的地址
// （保活要打给"提供这个映射的那台服务器"，否则映射撑不住）
func bestMapping(res ProbeResult) (net.IP, int, *net.UDPAddr, bool) {
	for _, s := range res.Samples {
		if s.Err != nil || s.IP == nil {
			continue
		}
		for _, srv := range DefaultStunServers {
			if srv.Name == s.Server {
				return s.IP, s.Port, resolveStun(srv), true
			}
		}
	}
	return nil, 0, nil, false
}
