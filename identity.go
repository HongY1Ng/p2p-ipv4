package main

// 数据面的身份与认证
//
// 打洞打出来的是一条【裸的】UDP 路径。任何知道你这一轮公网 IP:端口的人
// 都能往上面发 QUIC 握手包。如果数据面只是「自签证书 + InsecureSkipVerify」，
// 攻击者用自己的证书就能完成握手，然后直接访问你 --share 出去的端口
// （比如远程桌面），等于白送。
//
// 所以这里不传证书、也不传指纹，而是让两边【各自从同一个 token 派生密钥】：
//
//	token ──HKDF-SHA256──┬─ "server" ──> 服务端 ed25519 私钥
//	                     └─ "client" ──> 客户端 ed25519 私钥
//
// 服务端出示 server 证书、并要求对方出示证书；客户端出示 client 证书。
// 两边都在 VerifyPeerCertificate 里把【对端证书中的公钥】和【自己算出来的
// 期望公钥】逐字节比对。token 不一致 → 握手失败。
//
// 这样做的好处：不需要 CA、不需要交换证书指纹、不需要多一次往返。
// token 本身可以像地址一样靠人工粘贴传递，符合这个工具「零基础设施」的思路。
// 这也顺带解决了「打洞出来的路径无法确认对端身份」这个问题。

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	// alpnDataPlane 是数据面的 ALPN 标识。
	// 带上它可以让不匹配的协议在握手阶段就被拒掉。
	alpnDataPlane = "p2p-fwd/1"

	// hkdfInfo 是 HKDF 的 context 串，改它等于换一套密钥体系。
	hkdfInfo = "p2p-ipv4/data-plane/v1"

	roleServer = "server"
	roleClient = "client"
)

// deriveKey 从 token 派生某一角色的 ed25519 私钥。
// HKDF 是确定性的：同样的 token + 同样的角色，两端算出来的密钥完全一样。
func deriveKey(token, role string) ed25519.PrivateKey {
	r := hkdf.New(sha256.New, []byte(token), []byte(hkdfInfo), []byte(role))
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		// HKDF 是纯计算，不存在读失败的情况
		panic("hkdf: " + err.Error())
	}
	return ed25519.NewKeyFromSeed(seed)
}

// selfSignedCert 用给定私钥造一张自签证书。
// 自签本身不提供任何信任 —— 信任全部来自下面 pinPeer 里的公钥比对。
// 证书的有效期故意设得很宽：这张证书靠不靠得住和时间无关，只和公钥有关。
func selfSignedCert(priv ed25519.PrivateKey) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "p2p-data-plane"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<33, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// pinPeer 返回一个只认「指定公钥」的校验回调。
// 注意：这里必须报错而不是放行 —— 这是整条链路上唯一的认证点。
func pinPeer(expected ed25519.PublicKey) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("对端没有提供证书")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("解析对端证书失败: %w", err)
		}
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("对端证书用的不是 ed25519（收到 %T）", cert.PublicKey)
		}
		if !bytes.Equal(pub, expected) {
			return errors.New("token 不匹配")
		}
		return nil
	}
}

// serverTLSConfig 服务端：出示 server 证书，要求对方出示 client 证书。
func serverTLSConfig(token string) (*tls.Config, error) {
	cert, err := selfSignedCert(deriveKey(token, roleServer))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// 证书是自签的，没有 CA 链可验，所以这里只「要求对方必须出示证书」；
		// 真正的校验交给下面的 pinPeer。
		ClientAuth: tls.RequireAnyClientCert,
		VerifyPeerCertificate: pinPeer(
			deriveKey(token, roleClient).Public().(ed25519.PublicKey)),
		NextProtos: []string{alpnDataPlane},
		MinVersion: tls.VersionTLS13,
	}, nil
}

// clientTLSConfig 客户端：出示 client 证书，只认 server 公钥。
func clientTLSConfig(token string) (*tls.Config, error) {
	cert, err := selfSignedCert(deriveKey(token, roleClient))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// 自签证书没有 CA 可校验，所以关掉标准校验路径……
		InsecureSkipVerify: true,
		// ……换成对端公钥的精确比对。
		// 这不是「跳过校验」，是把校验方式从「信任 CA」换成「信任 token」。
		VerifyPeerCertificate: pinPeer(
			deriveKey(token, roleServer).Public().(ed25519.PublicKey)),
		NextProtos: []string{alpnDataPlane},
		MinVersion: tls.VersionTLS13,
	}, nil
}
