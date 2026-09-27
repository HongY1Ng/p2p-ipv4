package main

// 命令行入口
//
// 三个子命令：
//   probe     只探测 NAT 类型
//   advertise 广播模式 —— 打印本机地址，等待对方连进来
//   connect   连接模式 —— 拿着对方给的地址主动打洞
//
// 退出码：0 = 通道建立成功；1 = 失败；2 = 用法错误

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// secsFlag 让 --timeout 30 和 --timeout 30s 都能用。
// Go 标准库的 Duration 只认带单位的写法，对普通用户太不友好。
type secsFlag struct{ p *time.Duration }

func (f secsFlag) String() string {
	if f.p == nil {
		return "0s"
	}
	return f.p.String()
}

func (f secsFlag) Set(s string) error {
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil {
		*f.p = time.Duration(n) * time.Second
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("需要秒数（如 30）或带单位的时长（如 30s / 5m）")
	}
	*f.p = v
	return nil
}

// newSecsFlag 注册一个"秒数/时长"都能写的选项
func newSecsFlag(fs *flag.FlagSet, p *time.Duration, name string, def time.Duration, usage string) {
	*p = def
	fs.Var(secsFlag{p}, name, usage)
}

func main() {
	// 不带参数运行（比如双击 exe）时进入交互菜单 ——
	// 只打印帮助再退出，对普通用户等于"没法用"。
	if len(os.Args) < 2 {
		os.Exit(interactiveMenu())
	}

	var code int
	switch os.Args[1] {
	case "probe":
		code = cmdProbe(os.Args[2:])
	case "advertise":
		code = cmdAdvertise(os.Args[2:])
	case "connect":
		code = cmdConnect(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	case "version", "-V", "--version":
		fmt.Printf("%s %s\n", appName, version)
		return
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", os.Args[1])
		usage()
		code = 2
	}
	if code != 0 {
		pauseIfInteractive()
	}
	os.Exit(code)
}

// interactiveMenu 不带参数运行（双击 exe）时的交互菜单
func interactiveMenu() int {
	for {
		fmt.Println()
		hr()
		fmt.Printf("  %s %s —— 零基础设施 UDP 打洞工具\n", appName, version)
		hr()
		fmt.Println()
		fmt.Println("  [1] 探测本机 NAT 类型     （建议先跑这个，看打洞可不可行）")
		fmt.Println("  [2] 广播模式 —— 我这边等着，把我的地址给对方")
		fmt.Println("  [3] 连接模式 —— 我有对方的地址，主动连过去")
		fmt.Println("  [4] 用法说明")
		fmt.Println("  [0] 退出")
		fmt.Println()
		fmt.Print("请选择: ")

		choice, ok := readLine()
		if !ok {
			fmt.Println()
			return 0
		}

		switch choice {
		case "1":
			cmdProbe(nil)
		case "2":
			cmdAdvertise(nil)
		case "3":
			fmt.Print("\n请粘贴对方的地址（形如 1.2.3.4:56789）: ")
			addr, ok := readLine()
			if !ok {
				return 0
			}
			if addr == "" {
				warn("没有输入地址")
				continue
			}
			cmdConnect([]string{addr})
		case "4":
			usage()
		case "0", "q", "Q", "exit", "quit":
			return 0
		default:
			warn("无效选择: %q", choice)
		}
		fmt.Println()
	}
}

// reorderArgs 让 "--port 45679 1.2.3.4:56789" 和 "1.2.3.4:56789 --port 45679"
// 两种写法都能用（Go 的 flag 包只认"选项在前"）
func reorderArgs(args []string) []string {
	boolFlags := map[string]bool{"-no-hold": true, "--no-hold": true}
	var flags, pos []string
	i := 0
	for i < len(args) {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && !boolFlags[a] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags = append(flags, args[i+1])
				i += 2
				continue
			}
			i++
			continue
		}
		pos = append(pos, a)
		i++
	}
	return append(flags, pos...)
}

// listenUDP 绑定本地 UDP 端口；端口被占用时自动换随机端口
func listenUDP(port int) (*net.UDPConn, int, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil && port != 0 {
		warn("本地端口 %d 不可用（%v），改用随机端口", port, err)
		conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	}
	if err != nil {
		return nil, 0, err
	}
	return conn, conn.LocalAddr().(*net.UDPAddr).Port, nil
}

func resolveStun(srv StunServer) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", srv.Host, srv.Port))
	if err != nil {
		return nil
	}
	return a
}

func yesno(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

// ---------- probe ----------

func cmdProbe(args []string) int {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	port := fs.Int("port", DefaultPort, "本地 UDP 端口")
	var stunTO time.Duration
	newSecsFlag(fs, &stunTO, "stun-timeout", 3*time.Second, "每个 STUN 服务器的超时（默认 3 秒）")
	_ = fs.Parse(reorderArgs(args))

	conn, actual, err := listenUDP(*port)
	if err != nil {
		errf("无法绑定 UDP 端口: %v", err)
		return 1
	}
	defer conn.Close()

	banner("NAT 探测", fmt.Sprintf("本地 UDP 端口: %d", actual))
	info("向 %d 个 STUN 服务器查询（复用同一个 socket）...", len(DefaultStunServers))

	res := ProbeNAT(conn, stunTO, logf)
	printProbeReport(res)

	if res.Kind.Friendly() {
		return 0
	}
	return 1
}

func printProbeReport(res ProbeResult) {
	good := res.GoodSamples()

	fmt.Println()
	if len(good) == 0 {
		banner("✗ 探测失败",
			"所有 STUN 服务器都没有响应。",
			"",
			"可能原因：",
			"  1. 出站 UDP 被网络封锁（公司/校园网常见）",
			"  2. 本机防火墙拦了出站 UDP",
			"  3. DNS 解析失败")
		return
	}

	ips := res.DistinctIPs()
	ports := res.DistinctPorts()

	lines := []string{
		fmt.Sprintf("公网 IPv4       : %s", strings.Join(ips, ", ")),
		fmt.Sprintf("观察到的映射端口 : %v", ports),
		fmt.Sprintf("有效样本        : %d/%d", len(good), len(res.Samples)),
		fmt.Sprintf("映射稳定性      : %s", yesno(res.Stable, "稳定", "不稳定")),
	}
	if res.HasIPv6 {
		lines = append(lines, fmt.Sprintf("公网 IPv6       : 有  %s", res.IPv6Addr))
	} else {
		lines = append(lines, "公网 IPv6       : 无")
	}
	banner("探测结果", lines...)

	if len(ips) > 1 {
		warn("对不同目标的出口 IP 不同 —— 存在多出口/负载均衡，打洞会很不稳定。")
	}

	switch res.Kind {
	case NatEIM:
		okf("NAT 类型: %s", res.Kind)
		plain("    所有目标看到同一个映射端口 —— 对打洞最友好的类型。")
		plain("    两端都是 EIM 时，标准 UDP 打洞成功率通常有 90% 左右。")
	case NatAPDM:
		errf("NAT 类型: %s", res.Kind)
		plain("    映射端口随目标变化 —— 服务器看到的端口 ≠ 对端看到的端口。")
		plain("    标准 UDP 打洞会失败，端口预测也不可靠。")
		plain("    → 建议改用中继方案，或检查两端是否都有公网 IPv6。")
	default:
		warn("NAT 类型: 未知（样本不足）")
	}

	if res.HasIPv6 {
		fmt.Println()
		okf("本机有公网 IPv6 —— 若对方也有，直接用 IPv6 直连会简单可靠得多，根本不用打洞。")
	}
	fmt.Println()
}

// ---------- 结果汇报 ----------

func printSuccess(sess *Session) {
	st := sess.Stats()
	banner("✅ 通道建立成功",
		fmt.Sprintf("对方地址  : %s", st.Peer),
		fmt.Sprintf("往返延迟  : %s", fmtDur(st.RTTAvg)),
		fmt.Sprintf("延迟范围  : 最小 %s / 最大 %s", fmtDur(st.RTTMin), fmtDur(st.RTTMax)),
		fmt.Sprintf("收发包    : 发出 %d / 收到 %d / 往返确认 %d", st.Sent, st.Received, st.Pongs),
		fmt.Sprintf("本地端口  : %d", localPortOf(sess)),
		"",
		"双向都已验证通过（不只是「收到过包」，而是对方能回包）。",
		"",
		"接下来：",
		"  - 把本地 UDP 端口给需要直连的程序用",
		"  - 或在这条通道之上跑 WireGuard / QUIC 做加密隧道",
	)
}

func printFailure(sess *Session, reason string, peerGiven bool) {
	st := sess.Stats()
	lines := []string{
		fmt.Sprintf("失败原因  : %s", reason),
		fmt.Sprintf("发出/收到 : %d / %d 个包", st.Sent, st.Received),
	}
	if st.Foreign > 0 {
		lines = append(lines, fmt.Sprintf("非本协议包: %d 个（对方端口上有别的东西在跑？）", st.Foreign))
	}
	if peerGiven && st.Peer != "" {
		lines = append(lines, fmt.Sprintf("对方地址  : %s", st.Peer))
	} else {
		lines = append(lines, "对方地址  : 未获得")
	}
	lines = append(lines, "",
		"常见原因（按可能性排序）：",
		"  1. 任一端是【对称 NAT】—— 两端各跑 'p2p probe' 对比结果",
		"  2. 任一端在运营商 CGNAT 后面且端口随机化",
		"  3. 本机防火墙拦了入站 UDP（第一次运行要在弹窗里选「允许」）",
		"  4. 两端在同一个 CGNAT 内，而该 CGNAT 不支持回环(hairpinning)",
		"  5. 公司/校园网封了 UDP",
		"",
		"本工具按设计【不提供中继兜底】。若确认有一端是对称 NAT：",
		"  - 换用带中继的方案（自建 VPS + frp / wireguard）",
		"  - 或检查两端是否都有公网 IPv6（有的话直连更简单）",
	)
	banner("❌ 打洞失败", lines...)
}

func localPortOf(sess *Session) int {
	if a, ok := sess.conn.LocalAddr().(*net.UDPAddr); ok {
		return a.Port
	}
	return 0
}
