package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"easm-platform/internal/applog"
	"easm-platform/internal/cert"
	"easm-platform/internal/config"
	"easm-platform/internal/engine"
	"easm-platform/internal/scanner"
	"easm-platform/internal/scheduler"
	"easm-platform/internal/store"
	"easm-platform/internal/web"
)

func main() {
	applog.Init()
	cfgPath := "config.json"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()

	if err := st.SeedSettings(map[string]string{
		"naabu_path":            cfg.NaabuPath,
		"naabu_rate":            cfg.NaabuRate,
		"naabu_retries":         "2",
		"naabu_workers":         "25",
		"naabu_timeout":         "1s",
		"naabu_scan_type":       "c",
		"naabu_verify":          "0",
		"scan_timeout_min":      "60",
		"resource_monitor":      "1",
		"resource_cpu_percent":  "90",
		"resource_memory_mb":    "1024",
		"resource_duration_sec": "30",
		"realert_days":          strconv.Itoa(cfg.RealertDays),
		"alert_out_of_scope":    strconv.FormatBool(cfg.AlertOutOfScope),
		"feishu_webhook":        cfg.Feishu.Webhook,
		"feishu_secret":         cfg.Feishu.Secret,
	}); err != nil {
		log.Fatalf("初始化设置失败: %v", err)
	}
	if err := st.EnsureAdmin(cfg.Admin.User, cfg.Admin.Password); err != nil {
		log.Fatalf("初始化管理员账号失败: %v", err)
	}
	if err := st.SeedScanTasks(); err != nil {
		log.Fatalf("初始化扫描任务失败: %v", err)
	}

	// 启动自愈：上次进程遗留的 running/paused 执行此时已无对应 naabu 进程，统一修正为 stopped。
	if healed, err := st.HealStaleScans(); err != nil {
		applog.Warnf("扫描状态启动自愈失败: %v", err)
	} else if healed > 0 {
		applog.Warnf("扫描状态启动自愈：%d 个遗留的运行中/暂停执行已修正为已终止", healed)
	}

	eng := engine.New(st, cfg)
	sc := scanner.New(st, cfg, eng)
	sched := scheduler.New(st, func(taskID int64) (int64, error) { return sc.StartTask(taskID) })
	go sched.Run(context.Background())

	srv := web.New(st, cfg, sc, eng)
	handler := srv.Handler()

	httpOn := cfg.HTTPEndpointEnabled()
	if !httpOn && !cfg.HTTPSEnabled {
		log.Fatalf("HTTP 与 HTTPS 均未启用，请检查 config.json 的 http_enabled / https_enabled")
	}
	if cfg.HTTPSEnabled {
		// 首次启动自动生成有效期约 100 年的自签名证书并持久化，之后复用；已存在则不覆盖。
		generated, err := cert.EnsureSelfSigned(cfg.TLSCert, cfg.TLSKey, cfg.TLSHosts)
		if err != nil {
			log.Fatalf("准备 TLS 证书失败: %v", err)
		}
		if generated {
			applog.Infof("已自动生成自签名 TLS 证书（有效期约 100 年）: %s / %s", cfg.TLSCert, cfg.TLSKey)
		}
	}

	if httpOn {
		httpSrv := &http.Server{Addr: cfg.Listen, Handler: handler, ErrorLog: applog.NewServerErrorLogger()}
		go func() {
			applog.Infof("%s HTTP 启动: http://%s", cfg.AppName, cfg.Listen)
			if err := httpSrv.ListenAndServe(); err != nil {
				log.Fatalf("HTTP 服务退出: %v", err)
			}
		}()
	}
	if cfg.HTTPSEnabled {
		// 用 GetCertificate 动态加载证书：页面上传新证书后无需重启即可对新连接生效。
		// ErrorLog 降噪：客户端不信任自签名证书/端口扫描导致的握手失败不再当 error 刷屏。
		loader := cert.NewLoader(cfg.TLSCert, cfg.TLSKey)
		httpsSrv := &http.Server{
			Addr:     cfg.HTTPSListen,
			Handler:  handler,
			ErrorLog: applog.NewServerErrorLogger(),
			TLSConfig: &tls.Config{
				GetCertificate: loader.GetCertificate,
				MinVersion:     tls.VersionTLS12,
			},
		}
		go func() {
			applog.Infof("%s HTTPS 启动: https://%s（首次登录用 config.json 里的管理员账号，登录后请到“系统管理-账号”修改；自签名证书浏览器会提示不安全，属正常）", cfg.AppName, cfg.HTTPSListen)
			if err := httpsSrv.ListenAndServeTLS("", ""); err != nil {
				log.Fatalf("HTTPS 服务退出: %v", err)
			}
		}()
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	applog.Infof("收到退出信号，关闭中...")
	sc.Shutdown()
}
