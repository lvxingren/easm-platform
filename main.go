package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"easm-platform/internal/applog"
	"easm-platform/internal/buildinfo"
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
		switch os.Args[1] {
		case "-version", "--version", "version":
			fmt.Printf("灵瞰 · 资产测绘管理平台 %s\n", buildinfo.Version)
			return
		default:
			cfgPath = os.Args[1]
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	applog.Infof("%s %s 正在启动（配置文件：%s）", cfg.AppName, buildinfo.Version, cfgPath)
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()

	if err := st.SeedSettings(map[string]string{
		"naabu_path":            cfg.NaabuPath,
		"naabu_rate":            cfg.NaabuRate,
		"naabu_retries":         "2",
		"naabu_workers":         "100",
		"naabu_timeout":         "1s",
		"naabu_scan_type":       "c",
		"naabu_verify":          "0",
		"scan_timeout_min":      "0",
		"scan_concurrency":      "6",
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
	// 存量库性能调优：仅把仍等于旧默认值的并发/线程/速率升级到 2C4G 推荐值，保留用户自定义。
	st.UpgradePerformanceDefaults()
	// 日志级别：settings 优先（热生效），否则 config.log_level（默认 warn）。
	// 仅控制 stderr 输出；进程内环形缓冲始终全量，不影响运行日志页。
	logLevel := st.Setting("log_level")
	if logLevel == "" {
		logLevel = cfg.LogLevel
	}
	applog.SetMinLevel(logLevel)
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

	// 先同步绑定监听端口：端口被占用等问题能在此处立即以清晰信息报错（而非在 goroutine 里静默 fatal），
	// 只有绑定成功后才对外打印访问 URL，避免“报了地址却连不上”。
	var httpLn, httpsLn net.Listener
	if httpOn {
		ln, err := net.Listen("tcp", cfg.Listen)
		if err != nil {
			fmt.Fprintf(os.Stderr, "HTTP 监听 %s 失败（端口可能被占用，或已有实例在运行）: %v\n", cfg.Listen, err)
			os.Exit(1)
		}
		httpLn = ln
	}
	if cfg.HTTPSEnabled {
		ln, err := net.Listen("tcp", cfg.HTTPSListen)
		if err != nil {
			fmt.Fprintf(os.Stderr, "HTTPS 监听 %s 失败（端口可能被占用，或已有实例在运行）: %v\n", cfg.HTTPSListen, err)
			os.Exit(1)
		}
		httpsLn = ln
	}

	// 启动横幅：无视日志级别，直接打 stdout，确保用户总能看到可访问的 URL。
	printAccessBanner(cfg, httpOn)

	if httpOn {
		httpSrv := &http.Server{Handler: handler, ErrorLog: applog.NewServerErrorLogger()}
		go func() {
			applog.Infof("%s HTTP 服务已启动: http://%s", cfg.AppName, cfg.Listen)
			if err := httpSrv.Serve(httpLn); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP 服务退出: %v", err)
			}
		}()
	}
	if cfg.HTTPSEnabled {
		// 用 GetCertificate 动态加载证书：页面上传新证书后无需重启即可对新连接生效。
		// ErrorLog 降噪：客户端不信任自签名证书/端口扫描导致的握手失败不再当 error 刷屏。
		loader := cert.NewLoader(cfg.TLSCert, cfg.TLSKey)
		httpsSrv := &http.Server{
			Handler:  handler,
			ErrorLog: applog.NewServerErrorLogger(),
			TLSConfig: &tls.Config{
				GetCertificate: loader.GetCertificate,
				MinVersion:     tls.VersionTLS12,
			},
		}
		go func() {
			applog.Infof("%s HTTPS 服务已启动: https://%s（首次登录用 config.json 里的管理员账号，登录后请到“系统管理-账号”修改；自签名证书浏览器会提示不安全，属正常）", cfg.AppName, cfg.HTTPSListen)
			if err := httpsSrv.ServeTLS(httpsLn, "", ""); err != nil && err != http.ErrServerClosed {
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

// printAccessBanner 打印可直接访问的 URL 横幅到 stdout，不受日志级别（默认 warn）过滤影响，
// 确保启动后用户总能在终端看到入口地址（解决“启动后看不到 info 日志”的困惑）。
func printAccessBanner(cfg *config.Config, httpOn bool) {
	fmt.Printf("\n%s %s 已启动，可通过以下地址访问：\n", cfg.AppName, buildinfo.Version)
	if httpOn {
		fmt.Printf("  ➜ HTTP : %s\n", displayURL("http", cfg.Listen))
	}
	if cfg.HTTPSEnabled {
		fmt.Printf("  ➜ HTTPS: %s  (自签名证书，浏览器提示不安全属正常)\n", displayURL("https", cfg.HTTPSListen))
	}
	fmt.Printf("  首次登录账号：%s（密码见 config.json 的 admin.password，登录后请尽快修改）\n\n", cfg.Admin.User)
}

// displayURL 把监听地址（0.0.0.0:8443 / :8443 / 127.0.0.1:8443）转成便于点击的访问 URL；
// 全网卡监听时用 localhost 展示，并附注实际绑定地址。
func displayURL(scheme, addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return scheme + "://" + addr
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return fmt.Sprintf("%s://localhost:%s  (监听 %s)", scheme, port, addr)
	default:
		return fmt.Sprintf("%s://%s", scheme, addr)
	}
}
