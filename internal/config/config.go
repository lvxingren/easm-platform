package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	Listen          string   `json:"listen"`
	HTTPEnabled     *bool    `json:"http_enabled"`
	HTTPSEnabled    bool     `json:"https_enabled"`
	HTTPSListen     string   `json:"https_listen"`
	TLSCert         string   `json:"tls_cert"`
	TLSKey          string   `json:"tls_key"`
	TLSHosts        []string `json:"tls_hosts"`
	AppName         string   `json:"app_name"`
	DBPath          string   `json:"db_path"`
	LogLevel        string   `json:"log_level"`
	NaabuPath       string   `json:"naabu_path"`
	NaabuRate       string   `json:"naabu_rate"`
	RealertDays     int      `json:"realert_days"`
	AlertOutOfScope bool     `json:"alert_out_of_scope"`
	Feishu          struct {
		Webhook string `json:"webhook"`
		Secret  string `json:"secret"`
	} `json:"feishu"`
	Admin struct {
		User     string `json:"user"`
		Password string `json:"password"`
	} `json:"admin"`

	// path 记录配置文件的加载路径（未导出、不参与 JSON），供 Save 原子回写。
	path string
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = ":8000"
	}
	if c.AppName == "" {
		c.AppName = "灵瞰 · 资产测绘管理平台"
	}
	if c.DBPath == "" {
		c.DBPath = "data/easm.db"
	}
	if c.LogLevel == "" {
		c.LogLevel = "warn"
	}
	if c.NaabuPath == "" {
		c.NaabuPath = "naabu"
	}
	if c.NaabuRate == "" {
		c.NaabuRate = "5000"
	}
	if c.RealertDays <= 0 {
		c.RealertDays = 7
	}
	if c.HTTPSListen == "" {
		c.HTTPSListen = ":8443"
	}
	if c.TLSCert == "" {
		c.TLSCert = "data/certs/server.crt"
	}
	if c.TLSKey == "" {
		c.TLSKey = "data/certs/server.key"
	}
	if len(c.TLSHosts) == 0 {
		c.TLSHosts = []string{"localhost", "127.0.0.1"}
	}
	if c.Admin.User == "" {
		c.Admin.User = "admin"
	}
	if abs, err := filepath.Abs(path); err == nil {
		c.path = abs
	} else {
		c.path = path
	}
	return c, nil
}

// HTTPEndpointEnabled 报告是否启用明文 HTTP 监听；未显式配置时默认启用，保持对旧部署的兼容。
func (c *Config) HTTPEndpointEnabled() bool {
	return c.HTTPEnabled == nil || *c.HTTPEnabled
}

// Path 返回配置文件的加载路径（供页面展示与保存定位）。
func (c *Config) Path() string { return c.path }

// Save 以缩进 JSON 原子写回配置文件（临时文件 + rename）。
// 注意：监听地址与 HTTP/HTTPS 开关在进程启动时已绑定端口，Save 后需重启服务才生效；
// 证书文件的热重载不经过此处（见 cert.Loader）。
func (c *Config) Save() error {
	if c.path == "" {
		return fmt.Errorf("配置未关联文件路径，无法保存")
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}
