package main

// NAT 行为探测
//
// 核心原理：用【同一个 socket】向多个不同 AS 的 STUN 服务器查询。
//   - 所有目标看到同一个映射端口  -> EIM（端点无关映射）= 锥形 NAT，打洞友好
//   - 端口随目标变化              -> APDM（地址端口相关映射）= 对称 NAT，标准打洞必失败
//
// ⚠️ 最容易犯的错：每问一个目标就新建一个 socket。
//    那样源端口变了，映射端口当然不同，结论必然是错的。

import (
	"net"
	"sort"
	"time"
)

// NatKind NAT 映射行为
type NatKind int

const (
	NatUnknown NatKind = iota
	NatEIM             // 端点无关映射（锥形 NAT）
	NatAPDM            // 地址端口相关映射（对称 NAT）
)

func (k NatKind) String() string {
	switch k {
	case NatEIM:
		return "EIM (端点无关映射 / 锥形 NAT)"
	case NatAPDM:
		return "APDM (映射随目标变化 / 对称 NAT)"
	}
	return "未知"
}

// Friendly 是否对打洞友好
func (k NatKind) Friendly() bool { return k == NatEIM }

// Sample 对单个 STUN 服务器的一次观测
type Sample struct {
	Server string
	IP     net.IP
	Port   int
	Err    error
}

// ProbeResult 探测结果
type ProbeResult struct {
	Samples  []Sample
	PublicIP net.IP
	Kind     NatKind
	Stable   bool
	HasIPv6  bool
	IPv6Addr string
}

// GoodSamples 成功观测数
func (r ProbeResult) GoodSamples() []Sample {
	var out []Sample
	for _, s := range r.Samples {
		if s.Err == nil {
			out = append(out, s)
		}
	}
	return out
}

// DistinctPorts 去重后的映射端口（升序）
func (r ProbeResult) DistinctPorts() []int {
	set := map[int]bool{}
	for _, s := range r.GoodSamples() {
		set[s.Port] = true
	}
	var out []int
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// DistinctIPs 去重后的出口 IP
func (r ProbeResult) DistinctIPs() []string {
	set := map[string]bool{}
	for _, s := range r.GoodSamples() {
		if s.IP != nil {
			set[s.IP.String()] = true
		}
	}
	var out []string
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// ProbeNAT 用给定 socket 做完整探测。log 可为 nil。
func ProbeNAT(conn *net.UDPConn, timeout time.Duration, log func(format string, a ...any)) ProbeResult {
	if log == nil {
		log = func(string, ...any) {}
	}
	var res ProbeResult

	for _, srv := range DefaultStunServers {
		ip, port, err := StunQuery(conn, srv, timeout)
		res.Samples = append(res.Samples, Sample{Server: srv.Name, IP: ip, Port: port, Err: err})
		if err != nil {
			log("  [--] %-12s %s", srv.Name, err)
		} else {
			log("  [OK] %-12s -> %s:%d", srv.Name, ip, port)
		}
	}

	good := res.GoodSamples()
	if len(good) == 0 {
		res.Kind = NatUnknown
	} else {
		res.PublicIP = good[0].IP
		if len(res.DistinctPorts()) == 1 {
			res.Kind = NatEIM
		} else {
			res.Kind = NatAPDM
		}
	}

	// 稳定性：对第一个成功的服务器重复查询 3 次
	if len(good) > 0 {
		for _, srv := range DefaultStunServers {
			if srv.Name != good[0].Server {
				continue
			}
			seen := map[int]bool{}
			ok := 0
			for i := 0; i < 3; i++ {
				_, p, err := StunQuery(conn, srv, timeout)
				if err == nil {
					seen[p] = true
					ok++
				}
				time.Sleep(200 * time.Millisecond)
			}
			res.Stable = ok == 3 && len(seen) == 1
			break
		}
	}

	res.HasIPv6, res.IPv6Addr = detectGlobalIPv6()
	return res
}

// detectGlobalIPv6 从本机网卡里找可用的公网 IPv6（不做网络探测，纯本地判断）
func detectGlobalIPv6() (bool, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP
			if ip.To4() != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			// 2000::/3 = 全局单播
			if len(ip) == net.IPv6len && ip[0]&0xE0 == 0x20 {
				return true, ip.String()
			}
		}
	}
	return false, ""
}
