package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func parseCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("证书 PEM 解析失败: %s", path)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEnsureSelfSignedGeneratesHundredYearCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "certs", "server.crt")
	keyPath := filepath.Join(dir, "certs", "server.key")

	generated, err := EnsureSelfSigned(certPath, keyPath, []string{"easm.local", "192.0.2.5"})
	if err != nil {
		t.Fatal(err)
	}
	if !generated {
		t.Fatal("首次调用应生成证书")
	}

	c := parseCert(t, certPath)
	years := c.NotAfter.Sub(c.NotBefore).Hours() / 24 / 365
	if years < 99 || years > 101 {
		t.Fatalf("证书有效期应约 100 年，实际约 %.1f 年", years)
	}
	if !c.IsCA {
		t.Fatal("自签名证书应标记为 CA 以构成有效信任链")
	}
	// SAN 应包含默认回环与自定义 hosts
	wantDNS := map[string]bool{"localhost": false, "easm.local": false}
	for _, name := range c.DNSNames {
		if _, ok := wantDNS[name]; ok {
			wantDNS[name] = true
		}
	}
	for name, found := range wantDNS {
		if !found {
			t.Fatalf("证书 DNS SAN 缺少 %q，实际 %v", name, c.DNSNames)
		}
	}
	wantIP := map[string]bool{"127.0.0.1": false, "192.0.2.5": false}
	for _, ip := range c.IPAddresses {
		if _, ok := wantIP[ip.String()]; ok {
			wantIP[ip.String()] = true
		}
	}
	for ip, found := range wantIP {
		if !found {
			t.Fatalf("证书 IP SAN 缺少 %q，实际 %v", ip, c.IPAddresses)
		}
	}

	// 私钥权限必须收紧到 0600，避免泄露
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("私钥文件权限过宽: %v", info.Mode().Perm())
	}

	// 幂等：证书已存在时应复用而非重新生成
	before := parseCert(t, certPath)
	generated2, err := EnsureSelfSigned(certPath, keyPath, []string{"ignored.example"})
	if err != nil {
		t.Fatal(err)
	}
	if generated2 {
		t.Fatal("证书已存在时应复用，不应重新生成")
	}
	after := parseCert(t, certPath)
	if before.SerialNumber.String() != after.SerialNumber.String() {
		t.Fatalf("复用证书时序列号发生变化，说明被覆盖：%s != %s", before.SerialNumber, after.SerialNumber)
	}
}

func TestEnsureSelfSignedRejectsEmptyPaths(t *testing.T) {
	if _, err := EnsureSelfSigned("", "k.pem", nil); err == nil {
		t.Fatal("空证书路径应报错")
	}
	if _, err := EnsureSelfSigned("c.pem", "", nil); err == nil {
		t.Fatal("空私钥路径应报错")
	}
}

func TestApplySANDeduplicatesAndClassifies(t *testing.T) {
	tmpl := &x509.Certificate{}
	applySAN(tmpl, []string{"localhost", "easm.local", "127.0.0.1", "10.0.0.1", "  "})
	// localhost 默认已含，重复不应产生第二条
	count := 0
	for _, d := range tmpl.DNSNames {
		if d == "localhost" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("localhost 应去重为 1 条，实际 %d（%v）", count, tmpl.DNSNames)
	}
	hasIP := false
	for _, ip := range tmpl.IPAddresses {
		if ip.Equal(net.ParseIP("10.0.0.1")) {
			hasIP = true
		}
	}
	if !hasIP {
		t.Fatalf("自定义 IP 未并入 SAN: %v", tmpl.IPAddresses)
	}
}

// TestGeneratedCertServesTLS 验证生成的证书能真实用于 TLS 服务端（与 main 的 ListenAndServeTLS 同机制）。
func TestGeneratedCertServesTLS(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if _, err := EnsureSelfSigned(certPath, keyPath, []string{"localhost"}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok-https")) })
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.ServeTLS(ln, certPath, keyPath) }()
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("HTTPS 请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok-https" {
		t.Fatalf("HTTPS 响应异常: %d %q", resp.StatusCode, body)
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("未建立 TLS 连接或未返回服务端证书")
	}
	if cn := resp.TLS.PeerCertificates[0].Subject.CommonName; cn != "EASM" {
		t.Fatalf("服务端证书 CommonName=%q，期望 EASM", cn)
	}
}

func TestValidateWriteAndInspectUploadedPair(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "u.crt")
	kp := filepath.Join(dir, "u.key")
	if _, err := EnsureSelfSigned(cp, kp, []string{"upload.example"}); err != nil {
		t.Fatal(err)
	}
	certPEM, _ := os.ReadFile(cp)
	keyPEM, _ := os.ReadFile(kp)
	if err := ValidatePair(certPEM, keyPEM); err != nil {
		t.Fatalf("合法证书校验失败: %v", err)
	}
	// 不匹配的私钥应被拒绝
	other := t.TempDir()
	otherCrt := filepath.Join(other, "o.crt")
	otherKey := filepath.Join(other, "o.key")
	if _, err := EnsureSelfSigned(otherCrt, otherKey, nil); err != nil {
		t.Fatal(err)
	}
	mismatched, _ := os.ReadFile(otherKey)
	if err := ValidatePair(certPEM, mismatched); err == nil {
		t.Fatal("证书与不匹配私钥应校验失败")
	}
	if err := ValidatePair(nil, keyPEM); err == nil {
		t.Fatal("空证书应报错")
	}
	// WritePair 写入新路径并可 Inspect
	wp := filepath.Join(dir, "sub", "w.crt")
	wk := filepath.Join(dir, "sub", "w.key")
	if err := WritePair(wp, wk, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	info, err := Inspect(wp)
	if err != nil {
		t.Fatal(err)
	}
	if !info.SelfSigned || info.DaysLeft < 30000 {
		t.Fatalf("Inspect 结果异常: %+v", info)
	}
	if err := WritePair(filepath.Join(dir, "bad.crt"), filepath.Join(dir, "bad.key"), []byte("not-pem"), keyPEM); err == nil {
		t.Fatal("WritePair 应拒绝非法 PEM")
	}
}

func TestLoaderHotReloadsWhenFileChanges(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "s.crt")
	kp := filepath.Join(dir, "s.key")
	if _, err := EnsureSelfSigned(cp, kp, []string{"a.example"}); err != nil {
		t.Fatal(err)
	}
	loader := NewLoader(cp, kp)
	c1, err := loader.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := loader.GetCertificate(nil)
	if c1 != c2 {
		t.Fatal("文件未变时应命中缓存，返回同一证书")
	}
	// 生成另一对证书覆盖，并强制 mtime 变化，应触发热重载
	other := t.TempDir()
	otherCrt := filepath.Join(other, "n.crt")
	otherKey := filepath.Join(other, "n.key")
	if _, err := EnsureSelfSigned(otherCrt, otherKey, []string{"b.example"}); err != nil {
		t.Fatal(err)
	}
	newCert, _ := os.ReadFile(otherCrt)
	newKey, _ := os.ReadFile(otherKey)
	if err := WritePair(cp, kp, newCert, newKey); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(cp, future, future)
	_ = os.Chtimes(kp, future, future)
	c3, err := loader.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c3 == c1 {
		t.Fatal("证书文件更新后应热重载为新证书")
	}
}
