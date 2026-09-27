package main

// 数据面解复用的回归测试
//
// 这两个测试守着一个很容易踩的坑：
// 把已经打通的 *net.UDPConn 交给 quic.Transport 之后，我们自己的包
// 要靠 Transport.ReadNonQUICPacket 取回来。而 Transport 的读循环一旦
// 拿到错误就会【关掉整个 Transport】—— 所以 socket 上不能残留任何
// 过期的读超时（ProbeNAT 跑完就会留下一个）。

import (
	"context"
	"net"
	"testing"
	"time"
)

// 魔数首字节必须让 quic-go 认定「这不是 QUIC 包」：
// 判定规则是首字节的 bit7 和 bit6 都为 0。
func TestMagicIsNotQUIC(t *testing.T) {
	if protoMagic[0]&0xc0 != 0 {
		t.Fatalf("魔数 %q 首字节 0x%02x 带了 bit7/bit6，会被当成 QUIC 短包头",
			protoMagic, protoMagic[0])
	}
}

func demuxCase(t *testing.T, staleDeadline bool) {
	t.Helper()

	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer recv.Close()

	send, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer send.Close()

	if staleDeadline {
		// 模拟 ProbeNAT 跑完：最后一次 StunQuery 设的读超时留在 socket 上，
		// 而且已经过期了。
		_ = recv.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		time.Sleep(40 * time.Millisecond)
	}

	// 走真实路径：newDataPlane 负责在把 socket 交给 Transport 之前
	// 清掉残留的读/写超时。
	dp := newDataPlane(recv, fwdOptions{})
	defer dp.transport.Close()
	tr := dp.transport

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got := make(chan int, 1)
	go func() {
		buf := make([]byte, 2048)
		n, _, err := tr.ReadNonQUICPacket(ctx, buf)
		if err != nil {
			got <- -1
			return
		}
		got <- n
	}()

	time.Sleep(200 * time.Millisecond)

	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1),
		Port: recv.LocalAddr().(*net.UDPAddr).Port}
	pkt := buildPacket(pktPing, 1)
	if _, err := send.WriteToUDP(pkt, dst); err != nil {
		t.Fatal(err)
	}

	select {
	case n := <-got:
		if n != len(pkt) {
			t.Fatalf("收到 %d 字节，期望 %d", n, len(pkt))
		}
	case <-time.After(4 * time.Second):
		t.Fatal("超时：Transport 没有把我们的包交回来")
	}
}

// 干净 socket：应当正常
func TestNonQUICDemux(t *testing.T) { demuxCase(t, false) }

// 残留过期读超时 —— 这是 ProbeNAT 之后的真实状态。
// 这里守的是 newDataPlane 的契约：不管 socket 之前被谁设过超时，
// 交给 Transport 之后我们的包都必须还能收回来。
func TestNonQUICDemuxAfterStaleDeadline(t *testing.T) { demuxCase(t, true) }
