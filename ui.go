package main

// 终端输出（不引第三方库，纯标准库）

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	appName     = "p2p"
	version     = "0.2.0"
	DefaultPort = 45678
)

const boxWidth = 64

// stdoutIsTTY 判断输出是不是终端。
// 不是终端（重定向到文件/管道）时就不能用 \r 刷新同一行了。
var stdoutIsTTY = func() bool {
	st, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}()

// statusLine 覆盖刷新当前行；非终端环境下退化成普通换行输出
func statusLine(format string, a ...any) {
	if stdoutIsTTY {
		fmt.Printf("\r\x1b[K"+format, a...)
	} else {
		fmt.Printf(format+"\n", a...)
	}
}

func clearStatusLine() {
	if stdoutIsTTY {
		fmt.Print("\r\x1b[K")
	}
}

// fmtDur 把 Duration 显示成人能看懂的精度（毫秒级以内不显示成 "0s"）
func fmtDur(d time.Duration) string {
	switch {
	case d <= 0:
		return "<1ms"
	case d < time.Microsecond:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	case d < time.Millisecond:
		return fmt.Sprintf("%.1fµs", float64(d.Nanoseconds())/1000.0)
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(d.Nanoseconds())/1e6)
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}

func hr() { fmt.Println(strings.Repeat("=", boxWidth)) }

// humanBytes 把字节数显示成 KB / MB / GB
func humanBytes(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	case n < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	default:
		return fmt.Sprintf("%.2f GB", float64(n)/(1024*1024*1024))
	}
}

func logf(format string, a ...any) { fmt.Printf(format+"\n", a...) }

func info(format string, a ...any)  { fmt.Printf("[i] "+format+"\n", a...) }
func okf(format string, a ...any)   { fmt.Printf("[+] "+format+"\n", a...) }
func plain(format string, a ...any) { fmt.Printf(format+"\n", a...) }
func warn(format string, a ...any)  { fmt.Printf("[!] "+format+"\n", a...) }
func errf(format string, a ...any)  { fmt.Printf("[x] "+format+"\n", a...) }

// banner 打印一个大标题框
func banner(title string, lines ...string) {
	fmt.Println()
	hr()
	fmt.Printf("  %s\n", title)
	if len(lines) > 0 {
		hr()
		for _, l := range lines {
			fmt.Printf("  %s\n", l)
		}
	}
	hr()
	fmt.Println()
}

// highlight 把最关键的一行单独放大显示，方便用户复制
func highlight(label, value string) {
	fmt.Println()
	fmt.Printf("  %s\n", strings.Repeat("-", boxWidth-2))
	fmt.Printf("  %s\n", label)
	fmt.Println()
	fmt.Printf("      %s\n", value)
	fmt.Println()
	fmt.Printf("  %s\n", strings.Repeat("-", boxWidth-2))
	fmt.Println()
}

// statusStart 打印一行"进行中"，返回一个可以把它覆盖掉的函数
func statusStart(msg string) func() {
	fmt.Printf("\r\x1b[K%s", msg)
	start := time.Now()
	return func() { fmt.Printf("\r\x1b[K"); _ = start }
}

// countdown 在等待期间持续刷新一行状态
func startSpinner(msg string, stop <-chan struct{}) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	frames := []string{"|", "/", "-", "\\"}
	i := 0
	start := time.Now()
	for {
		select {
		case <-stop:
			fmt.Printf("\r\x1b[K")
			return
		case <-ticker.C:
			fmt.Printf("\r\x1b[K%s %s  (%ds)", msg, frames[i%len(frames)], int(time.Since(start).Seconds()))
			i++
		}
	}
}

// ---------- 共享的 stdin 读取 ----------
//
// 为什么需要这个：
//   打洞时会起一个后台 goroutine 读 stdin（等用户粘贴对方地址），
//   而主菜单也要读 stdin。如果两边各自 bufio.NewScanner(os.Stdin)，
//   会互相把对方的输入吃掉。
//   所以统一由这里一个 goroutine 读，其他人从 channel 取。

var stdinLines = make(chan string, 32)

func init() {
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			stdinLines <- sc.Text()
		}
		close(stdinLines)
	}()
}

// readLine 阻塞读一行（已去掉首尾空白）。stdin 已关闭时 ok=false。
func readLine() (string, bool) {
	line, ok := <-stdinLines
	if !ok {
		return "", false
	}
	return strings.TrimSpace(line), true
}

// readLineTimeout 带超时读一行。第三个返回值表示是否超时。
func readLineTimeout(d time.Duration) (line string, ok bool, timedOut bool) {
	select {
	case l, k := <-stdinLines:
		return strings.TrimSpace(l), k, false
	case <-time.After(d):
		return "", true, true
	}
}

// usage 打印帮助
func usage() {
	fmt.Printf(`%s %s —— 零基础设施的 UDP 打洞工具（不需要任何服务器）

用法:
  %s probe                              只探测本机 NAT 类型
  %s advertise [选项]                   广播模式：打印本机地址，等待对方
  %s connect <ip:port> [选项]           连接模式：向对方打洞

通用选项:
  --port N        本地 UDP 端口（默认 %d，两端必须一致）
  --timeout N     总超时秒数（默认 300）
  --wait N        打洞尝试多少秒后判定失败（默认 60）

advertise 专属:
  --prompt N      多少秒没收到对方的包就提示粘贴对方地址（默认 20）
  --no-hold       成功后不保持通道，直接退出

数据面（可选）—— 打通之后直接在这条通道上跑 TCP 转发:
  --share P       开放本机 TCP 端口 P 给对方（可重复，也可用逗号分隔）
                  写成 P=HOST:PORT 可以转到内网另一台机器
  --forward L:R   本地监听 L，连上来的流量转发到【对方】的 R 端口
  --token S       共享密钥，两端必须一致
                  只在有 --share 的那一侧可以省略（会自动生成并打印）
  --bind ADDR     --forward 的本地监听地址（默认 127.0.0.1，不对外暴露）

例子:
  纯打洞
    A 机:  %s advertise
    B 机:  %s connect 1.2.3.4:56789

  把家里的远程桌面（3389）拉出来用
    家里:  %s advertise --share 3389
           把打印出来的【地址】和【数据面密钥】都发给外面
    外面:  %s connect 1.2.3.4:56789 --forward 13389:3389 --token <密钥>
           然后 RDP 连 127.0.0.1:13389 即可

提示:
  - 两端请使用同一个 --port
  - 第一次运行请在防火墙弹窗里选择「允许」
  - --share 是白名单：没列出来的端口一律拒绝
  - 数据面必须两端 token 一致，否则握不上手（这是唯一的身份校验）
  - 本工具不做中继兜底：打不通就是打不通，会明确告诉你原因
`, appName, version, appName, appName, appName, DefaultPort,
		appName, appName, appName, appName)
}

// pauseIfInteractive 双击运行时（输出是终端、程序即将退出）
// 停顿一下，免得窗口一闪而过看不到报错
func pauseIfInteractive() {
	if !stdoutIsTTY {
		return
	}
	fmt.Print("\n按回车退出 ...")
	readLine()
}
