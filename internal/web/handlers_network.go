package web

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"easm-platform/internal/cert"
)

// validateListenAddr 校验 host:port 监听地址格式（host 可为空，表示所有网卡）。
func validateListenAddr(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return fmt.Errorf("监听地址不能为空")
	}
	if _, port, err := net.SplitHostPort(addr); err != nil || port == "" {
		return fmt.Errorf("监听地址格式错误 %q，应为 host:port，例如 0.0.0.0:8443 或 127.0.0.1:8443", addr)
	}
	return nil
}

// splitHostList 解析逗号/换行/空格分隔的主机列表并去重。
func splitHostList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(c rune) bool { return c == ',' || c == '\n' || c == '\r' || c == ' ' })
	out := make([]string, 0, len(fields))
	seen := map[string]bool{}
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// apiSaveNetwork 保存 HTTP/HTTPS 开关、监听地址与自签名证书 SAN 主机到 config.json（仅 admin）。
// 监听端口在进程启动时已绑定，保存后需重启服务才生效；证书上传走 apiUploadCert 且热生效。
func (s *Server) apiSaveNetwork(w http.ResponseWriter, r *http.Request) {
	httpEnabled := r.FormValue("http_enabled") == "on"
	httpsEnabled := r.FormValue("https_enabled") == "on"
	if !httpEnabled && !httpsEnabled {
		writeJSON(w, 400, map[string]string{"error": "HTTP 与 HTTPS 至少需要启用一个，否则服务无法对外提供"})
		return
	}
	listen := strings.TrimSpace(r.FormValue("listen"))
	httpsListen := strings.TrimSpace(r.FormValue("https_listen"))
	if httpEnabled {
		if err := validateListenAddr(listen); err != nil {
			writeJSON(w, 400, map[string]string{"error": "HTTP " + err.Error()})
			return
		}
	}
	if httpsEnabled {
		if err := validateListenAddr(httpsListen); err != nil {
			writeJSON(w, 400, map[string]string{"error": "HTTPS " + err.Error()})
			return
		}
	}
	hosts := splitHostList(r.FormValue("tls_hosts"))

	s.cfg.HTTPEnabled = &httpEnabled
	s.cfg.HTTPSEnabled = httpsEnabled
	if listen != "" {
		s.cfg.Listen = listen
	}
	if httpsListen != "" {
		s.cfg.HTTPSListen = httpsListen
	}
	s.cfg.TLSHosts = hosts
	if err := s.cfg.Save(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存 config.json 失败：" + err.Error()})
		return
	}
	s.audit(r, "修改网络配置", s.cfg.Path(),
		fmt.Sprintf("http=%v(%s) https=%v(%s) hosts=%s", httpEnabled, listen, httpsEnabled, httpsListen, strings.Join(hosts, ",")))
	writeJSON(w, 200, map[string]interface{}{
		"ok": "1", "restart": "1",
		"message": "网络配置已保存到 config.json。监听地址与开关需重启服务后生效：sudo systemctl restart easm（证书上传为热生效，无需重启）。",
	})
}

// apiUploadCert 接收上传的证书与私钥（文件或 PEM 文本），校验匹配后写入 tls_cert/tls_key。
// 采用热重载，写入后新的 HTTPS 连接立即使用新证书，无需重启（仅 admin）。
func (s *Server) apiUploadCert(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(4 << 20); err != nil {
		if err2 := r.ParseForm(); err2 != nil {
			writeJSON(w, 400, map[string]string{"error": "读取上传内容失败：" + err.Error()})
			return
		}
	}
	certPEM, err := readPEMInput(r, "cert_file", "cert_pem")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "读取证书失败：" + err.Error()})
		return
	}
	keyPEM, err := readPEMInput(r, "key_file", "key_pem")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "读取私钥失败：" + err.Error()})
		return
	}
	if err := cert.WritePair(s.cfg.TLSCert, s.cfg.TLSKey, certPEM, keyPEM); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	info, _ := cert.Inspect(s.cfg.TLSCert)
	s.audit(r, "上传 TLS 证书", s.cfg.TLSCert, "")
	writeJSON(w, 200, map[string]interface{}{
		"ok": "1", "info": info,
		"message": "证书已保存并热生效，新的 HTTPS 连接会立即使用新证书，无需重启。",
	})
}

// readPEMInput 优先读取上传文件字段，其次读取粘贴的 PEM 文本域。
func readPEMInput(r *http.Request, fileField, textField string) ([]byte, error) {
	if file, hdr, err := r.FormFile(fileField); err == nil {
		defer file.Close()
		if strings.TrimSpace(hdr.Filename) != "" {
			data, err := io.ReadAll(io.LimitReader(file, 2<<20))
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(string(data)) != "" {
				return data, nil
			}
		}
	}
	if text := strings.TrimSpace(r.FormValue(textField)); text != "" {
		return []byte(text), nil
	}
	return nil, fmt.Errorf("未提供内容（可上传文件或粘贴 PEM 文本）")
}
