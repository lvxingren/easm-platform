// Package cert 提供自签名 TLS 证书的生成与复用，让平台 HTTPS「开箱即用」：
// 首次启动自动签发一张有效期约 100 年的自签名证书并持久化，之后直接复用，
// 无需在打包或部署时手工准备证书。如需使用正式 CA 证书，把证书/私钥放到
// 配置指定路径即可（存在则不会被覆盖）。
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultValidity 是自签名证书有效期：约 100 年，免去频繁更换。
const DefaultValidity = 100 * 365 * 24 * time.Hour

// EnsureSelfSigned 确保证书与私钥存在：
// 两者都已存在时直接复用（返回 false，不覆盖，便于用户替换为正式证书）；
// 否则生成一张有效期约 100 年的自签名证书并写盘（返回 true）。
// hosts 为附加 SAN（DNS 名或 IP），localhost / 127.0.0.1 / ::1 始终包含。
func EnsureSelfSigned(certPath, keyPath string, hosts []string) (bool, error) {
	if strings.TrimSpace(certPath) == "" || strings.TrimSpace(keyPath) == "" {
		return false, fmt.Errorf("TLS 证书或私钥路径为空")
	}
	if fileExists(certPath) && fileExists(keyPath) {
		return false, nil
	}
	if err := generate(certPath, keyPath, hosts); err != nil {
		return false, err
	}
	return true, nil
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func generate(certPath, keyPath string, hosts []string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("生成 ECDSA 私钥失败: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("生成证书序列号失败: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"灵瞰 · 外部攻击面管理平台"},
			CommonName:   "EASM",
		},
		NotBefore:             now.Add(-time.Hour), // 容忍轻微的时钟偏差
		NotAfter:              now.Add(DefaultValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	applySAN(tmpl, hosts)

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("签发自签名证书失败: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("序列化私钥失败: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return fmt.Errorf("创建私钥目录失败: %w", err)
	}
	if err := writePEM(certPath, 0o644, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return fmt.Errorf("写入证书失败: %w", err)
	}
	if err := writePEM(keyPath, 0o600, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("写入私钥失败: %w", err)
	}
	return nil
}

// applySAN 把回环地址与配置的 hosts 归类到 DNSNames / IPAddresses，并去重排序保证确定性。
func applySAN(tmpl *x509.Certificate, hosts []string) {
	dnsSet := map[string]struct{}{}
	ipSet := map[string]struct{}{}
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" {
			return
		}
		if ip := net.ParseIP(h); ip != nil {
			ipSet[ip.String()] = struct{}{}
			return
		}
		dnsSet[h] = struct{}{}
	}
	for _, h := range []string{"localhost", "127.0.0.1", "::1"} {
		add(h)
	}
	for _, h := range hosts {
		add(h)
	}
	for d := range dnsSet {
		tmpl.DNSNames = append(tmpl.DNSNames, d)
	}
	sort.Strings(tmpl.DNSNames)
	for ip := range ipSet {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
}

func writePEM(path string, mode os.FileMode, block *pem.Block) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		return err
	}
	// 显式 chmod，避免 umask 放宽私钥权限。
	return os.Chmod(path, mode)
}

// Loader 支持 TLS 证书热重载：每次握手按证书/私钥文件的修改时间决定是否重新加载，
// 页面上传新证书后新连接立即生效，无需重启服务。
type Loader struct {
	certPath  string
	keyPath   string
	mu        sync.RWMutex
	cached    *tls.Certificate
	certMTime time.Time
	keyMTime  time.Time
}

// NewLoader 创建绑定到指定证书/私钥路径的热重载加载器。
func NewLoader(certPath, keyPath string) *Loader {
	return &Loader{certPath: certPath, keyPath: keyPath}
}

// GetCertificate 实现 tls.Config.GetCertificate，供 HTTPS 服务端动态取证书。
func (l *Loader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	ci, err := os.Stat(l.certPath)
	if err != nil {
		return nil, err
	}
	ki, err := os.Stat(l.keyPath)
	if err != nil {
		return nil, err
	}
	l.mu.RLock()
	cached, cm, km := l.cached, l.certMTime, l.keyMTime
	l.mu.RUnlock()
	if cached != nil && cm.Equal(ci.ModTime()) && km.Equal(ki.ModTime()) {
		return cached, nil
	}
	loaded, err := tls.LoadX509KeyPair(l.certPath, l.keyPath)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.cached = &loaded
	l.certMTime = ci.ModTime()
	l.keyMTime = ki.ModTime()
	l.mu.Unlock()
	return &loaded, nil
}

// ValidatePair 校验上传的证书与私钥 PEM：可解析且公私钥匹配（tls.X509KeyPair 会校验匹配）。
func ValidatePair(certPEM, keyPEM []byte) error {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return fmt.Errorf("证书或私钥内容为空")
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("证书与私钥无效或不匹配：%w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("证书不是有效的 PEM 格式")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("证书解析失败：%w", err)
	}
	return nil
}

// WritePair 校验通过后把证书/私钥写入指定路径（证书 0644、私钥 0600，自动建目录）。
func WritePair(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := ValidatePair(certPEM, keyPEM); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return fmt.Errorf("创建私钥目录失败: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("写入证书失败: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("写入私钥失败: %w", err)
	}
	return nil
}

// Info 描述当前证书，供系统设置页展示。
type Info struct {
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	DNSNames    []string `json:"dns_names"`
	IPAddresses []string `json:"ip_addresses"`
	SelfSigned  bool     `json:"self_signed"`
	DaysLeft    int      `json:"days_left"`
}

// Inspect 读取并解析证书文件，返回可展示的摘要；文件不存在或非法时返回错误。
func Inspect(certPath string) (*Info, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("证书不是有效的 PEM 格式")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(c.IPAddresses))
	for _, ip := range c.IPAddresses {
		ips = append(ips, ip.String())
	}
	return &Info{
		Issuer:      c.Issuer.String(),
		Subject:     c.Subject.String(),
		NotBefore:   c.NotBefore.Format("2006-01-02 15:04"),
		NotAfter:    c.NotAfter.Format("2006-01-02 15:04"),
		DNSNames:    c.DNSNames,
		IPAddresses: ips,
		SelfSigned:  c.Issuer.String() == c.Subject.String(),
		DaysLeft:    int(time.Until(c.NotAfter).Hours() / 24),
	}, nil
}
