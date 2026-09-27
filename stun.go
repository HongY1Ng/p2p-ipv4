package main

// STUN 客户端（自实现，零第三方依赖）
//
// 为什么不用现成的库：这个工具要发到 GitHub 让普通人下载，
// 依赖越少越好；而且国内访问 proxy.golang.org 会被墙，
// 纯标准库可以让 `go build` 在完全离线的情况下成功。

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	stunMagicCookie = 0x2112A442
	stunBindingReq  = 0x0001
	stunBindingResp = 0x0101
	attrMapped      = 0x0001
	attrXorMapped   = 0x0020
)

// StunServer 一个 STUN 服务器目标
type StunServer struct {
	Name string
	Host string
	Port int
}

// DefaultStunServers 尽量分散在不同 AS，
// 这样"映射端口是否随目标变化"才有判断力（EIM vs 对称 NAT）。
var DefaultStunServers = []StunServer{
	{"Google", "stun.l.google.com", 19302},
	{"Cloudflare", "stun.cloudflare.com", 3478},
	{"Nextcloud", "stun.nextcloud.com", 443},
	{"Xiaomi", "stun.miwifi.com", 3478},
	{"Antisip", "stun.antisip.com", 3478},
	{"Epygi", "stun.epygi.com", 3478},
	{"Voiparound", "stun.voiparound.com", 3478},
}

// StunQuery 用【给定的 socket】向 STUN 服务器查询本机公网映射。
//
// 必须复用同一个 socket —— NAT 映射绑定的是"内网 socket"，
// 换 socket 就等于换内网源端口，得到的映射对后续打洞毫无意义。
func StunQuery(conn *net.UDPConn, srv StunServer, timeout time.Duration) (net.IP, int, error) {
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", srv.Host, srv.Port))
	if err != nil {
		return nil, 0, err
	}

	req := buildBindingRequest()
	if _, err := conn.WriteToUDP(req.packet, addr); err != nil {
		return nil, 0, err
	}

	deadline := time.Now().Add(timeout)
	buf := make([]byte, 1500)
	for {
		if !time.Now().Before(deadline) {
			return nil, 0, errors.New("超时")
		}
		_ = conn.SetReadDeadline(deadline)
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, 0, errors.New("超时")
		}
		// 忽略来自其他地址的包（可能是上一次探测的迟到响应）
		if !from.IP.Equal(addr.IP) || from.Port != addr.Port {
			continue
		}
		ip, port, err := parseStunResponse(buf[:n], req.txn)
		if err != nil {
			continue
		}
		return ip, port, nil
	}
}

type bindingRequest struct {
	packet []byte
	txn    [12]byte
}

func buildBindingRequest() bindingRequest {
	var br bindingRequest
	br.packet = make([]byte, 20)
	binary.BigEndian.PutUint16(br.packet[0:], stunBindingReq)
	binary.BigEndian.PutUint16(br.packet[2:], 0)
	binary.BigEndian.PutUint32(br.packet[4:], stunMagicCookie)
	_, _ = rand.Read(br.txn[:])
	copy(br.packet[8:], br.txn[:])
	return br
}

func parseStunResponse(b []byte, txn [12]byte) (net.IP, int, error) {
	if len(b) < 20 {
		return nil, 0, errors.New("响应过短")
	}
	if binary.BigEndian.Uint16(b[0:]) != stunBindingResp {
		return nil, 0, errors.New("不是 Binding Success")
	}
	if binary.BigEndian.Uint32(b[4:]) != stunMagicCookie {
		return nil, 0, errors.New("magic cookie 不符")
	}
	for i := 0; i < 12; i++ {
		if b[8+i] != txn[i] {
			return nil, 0, errors.New("事务 ID 不符")
		}
	}

	msgLen := int(binary.BigEndian.Uint16(b[2:]))
	pos := 20
	end := 20 + msgLen
	if end > len(b) {
		end = len(b)
	}
	for pos+4 <= end {
		atype := binary.BigEndian.Uint16(b[pos:])
		alen := int(binary.BigEndian.Uint16(b[pos+2:]))
		if pos+4+alen > len(b) {
			break
		}
		val := b[pos+4 : pos+4+alen]
		// XOR-MAPPED-ADDRESS / MAPPED-ADDRESS 的结构：
		//   val[0]   保留
		//   val[1]   地址族 (1 = IPv4)
		//   val[2:4] 端口
		//   val[4:8] 地址
		if (atype == attrXorMapped || atype == attrMapped) && alen >= 8 && val[1] == 0x01 {
			port := int(binary.BigEndian.Uint16(val[2:4]))
			ip := net.IPv4(val[4], val[5], val[6], val[7])
			if atype == attrXorMapped {
				port ^= stunMagicCookie >> 16
				ip = net.IPv4(val[4]^0x21, val[5]^0x12, val[6]^0xA4, val[7]^0x42)
			}
			return ip.To4(), port, nil
		}
		pos += 4 + alen + ((4 - alen%4) % 4)
	}
	return nil, 0, errors.New("没有 MAPPED-ADDRESS 属性")
}
