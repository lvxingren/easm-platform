package web

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"easm-platform/internal/cert"
	"easm-platform/internal/config"
	"easm-platform/internal/engine"
	"easm-platform/internal/scanner"
	"easm-platform/internal/store"
)

// newNetworkTestServer 用 config.Load 构造带文件路径的配置，使 cfg.Save() 可写回临时 config.json。
func newNetworkTestServer(t *testing.T) (*Server, *store.Store, *config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	certsDir := filepath.Join(dir, "certs")
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON := `{
  "listen": "127.0.0.1:18080",
  "https_enabled": true,
  "https_listen": "127.0.0.1:18443",
  "tls_cert": "` + filepath.Join(certsDir, "s.crt") + `",
  "tls_key": "` + filepath.Join(certsDir, "s.key") + `",
  "db_path": "` + dbPath + `",
  "naabu_path": "naabu",
  "admin": {"user":"admin","password":"x"}
}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.New(st, cfg)
	srv := New(st, cfg, scanner.New(st, cfg, eng), eng)
	for _, u := range []struct{ name, role string }{{"admin", "admin"}, {"viewer", "viewer"}} {
		id, err := st.CreateUser(u.name, "pw", u.role, "")
		if err != nil {
			t.Fatal(err)
		}
		srv.sessions["test-"+u.name] = session{userID: id, username: u.name, role: u.role, exp: time.Now().Add(time.Hour)}
	}
	return srv, st, cfg, cfgPath
}

func TestApiSaveNetworkPersistsConfig(t *testing.T) {
	srv, _, _, cfgPath := newNetworkTestServer(t)
	form := url.Values{}
	form.Set("http_enabled", "on")
	form.Set("https_enabled", "on")
	form.Set("listen", "0.0.0.0:18080")
	form.Set("https_listen", "0.0.0.0:18443")
	form.Set("tls_hosts", "easm.example.com, 10.0.0.9")
	if rec := scanFormRequest(srv, "/api/settings/network", "admin", form); rec.Code != http.StatusOK {
		t.Fatalf("保存网络配置状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Listen != "0.0.0.0:18080" || reloaded.HTTPSListen != "0.0.0.0:18443" {
		t.Fatalf("config.json 未正确持久化: %+v", reloaded)
	}
	if len(reloaded.TLSHosts) != 2 || reloaded.TLSHosts[0] != "easm.example.com" || reloaded.TLSHosts[1] != "10.0.0.9" {
		t.Fatalf("tls_hosts 保存错误: %+v", reloaded.TLSHosts)
	}
	if reloaded.HTTPEnabled == nil || !*reloaded.HTTPEnabled {
		t.Fatalf("http_enabled 未保存为 true: %+v", reloaded.HTTPEnabled)
	}
}

func TestApiSaveNetworkValidationAndRBAC(t *testing.T) {
	srv, _, _, _ := newNetworkTestServer(t)
	// HTTP 与 HTTPS 全关应拒绝
	none := url.Values{}
	none.Set("listen", "0.0.0.0:18080")
	none.Set("https_listen", "0.0.0.0:18443")
	if rec := scanFormRequest(srv, "/api/settings/network", "admin", none); rec.Code != http.StatusBadRequest {
		t.Fatalf("HTTP/HTTPS 全关应 400，实际 %d", rec.Code)
	}
	// 非法监听地址应拒绝
	bad := url.Values{}
	bad.Set("http_enabled", "on")
	bad.Set("listen", "not-an-addr")
	bad.Set("https_listen", "0.0.0.0:18443")
	if rec := scanFormRequest(srv, "/api/settings/network", "admin", bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法监听地址应 400，实际 %d", rec.Code)
	}
	// viewer 无权
	if rec := scanFormRequest(srv, "/api/settings/network", "viewer", none); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 应 403，实际 %d", rec.Code)
	}
}

func TestApiUploadCertWritesAndHotApplies(t *testing.T) {
	srv, _, cfg, _ := newNetworkTestServer(t)
	gen := t.TempDir()
	genCrt := filepath.Join(gen, "g.crt")
	genKey := filepath.Join(gen, "g.key")
	if _, err := cert.EnsureSelfSigned(genCrt, genKey, []string{"uploaded.example"}); err != nil {
		t.Fatal(err)
	}
	certPEM, _ := os.ReadFile(genCrt)
	keyPEM, _ := os.ReadFile(genKey)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	cf, _ := mw.CreateFormFile("cert_file", "g.crt")
	_, _ = cf.Write(certPEM)
	kf, _ := mw.CreateFormFile("key_file", "g.key")
	_, _ = kf.Write(keyPEM)
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/settings/cert", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "easm_sid", Value: "test-admin"})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("上传证书状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	info, err := cert.Inspect(cfg.TLSCert)
	if err != nil {
		t.Fatalf("上传后证书不可解析: %v", err)
	}
	found := false
	for _, d := range info.DNSNames {
		if d == "uploaded.example" {
			found = true
		}
	}
	if !found {
		t.Fatalf("上传证书未写入生效路径: %+v", info)
	}

	// 不匹配的证书/私钥应被拒绝
	var bad bytes.Buffer
	bw := multipart.NewWriter(&bad)
	bcf, _ := bw.CreateFormFile("cert_file", "g.crt")
	_, _ = bcf.Write(certPEM)
	bkf, _ := bw.CreateFormFile("key_file", "bad.key")
	_, _ = bkf.Write([]byte("-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n"))
	_ = bw.Close()
	breq := httptest.NewRequest(http.MethodPost, "/api/settings/cert", &bad)
	breq.Header.Set("Content-Type", bw.FormDataContentType())
	breq.AddCookie(&http.Cookie{Name: "easm_sid", Value: "test-admin"})
	brec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(brec, breq)
	if brec.Code != http.StatusBadRequest {
		t.Fatalf("非法私钥应 400，实际 %d 响应=%s", brec.Code, brec.Body.String())
	}

	// viewer 无权上传
	if rec := scanFormRequest(srv, "/api/settings/cert", "viewer", url.Values{}); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer 上传证书应 403，实际 %d", rec.Code)
	}
}
