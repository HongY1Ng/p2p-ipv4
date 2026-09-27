// 交叉编译出各平台的可执行文件，产物在 dist/ 下
//
// 用法（任意平台，只要装了 Go）：
//   go run build.go
//
// 这里用 Go 写构建脚本，好处是 Windows / Linux / macOS 都能直接用，
// 不用同时维护 .ps1 和 .sh 两份。

//go:build ignore

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

var targets = []struct {
	os   string
	arch string
}{
	{"windows", "amd64"},
	{"windows", "arm64"},
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
}

func main() {
	if err := os.MkdirAll("dist", 0o755); err != nil {
		die(err)
	}

	// -s -w 去掉调试信息，二进制能小 30% 左右
	ldflags := "-s -w"

	for _, t := range targets {
		name := fmt.Sprintf("p2p_%s_%s", t.os, t.arch)
		if t.os == "windows" {
			name += ".exe"
		}
		out := filepath.Join("dist", name)
		fmt.Printf("  building %-28s ... ", name)

		cmd := exec.Command("go", "build", "-trimpath", "-ldflags="+ldflags, "-o", out, ".")
		cmd.Env = append(os.Environ(), "GOOS="+t.os, "GOARCH="+t.arch, "CGO_ENABLED=0")
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println("失败")
			die(err)
		}
		fi, _ := os.Stat(out)
		fmt.Printf("OK  (%.1f MB)\n", float64(fi.Size())/(1<<20))
	}

	// 本机版本额外复制一份到仓库根目录，方便直接跑
	local := "p2p"
	if runtime.GOOS == "windows" {
		local = "p2p.exe"
	}
	fmt.Printf("\n完成！产物在 dist/ 下。\n")
	fmt.Printf("本机可直接运行: go build -o %s .\n", local)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "错误:", err)
	os.Exit(1)
}
