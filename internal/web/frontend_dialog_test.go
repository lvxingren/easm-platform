package web

import (
	"regexp"
	"strings"
	"testing"
)

// nativeDialogCall 匹配浏览器原生 alert/confirm/prompt 调用；
// 排除 appConfirm(、alertStatusName( 等带前缀的自定义函数与 CSS 类名。
var nativeDialogCall = regexp.MustCompile(`(^|[^.A-Za-z0-9_])(?:window\.)?(alert|confirm|prompt)\s*\(`)

// TestNoNativeBrowserDialogs 锁定前端弹窗契约：所有页面都必须使用平台统一的
// appConfirm / appPrompt / appWhitelistDialog（.modal 样式），不得再调用浏览器原生
// alert/confirm/prompt——Chrome 会显示成「127.0.0.1:8443 显示」，无法与平台样式统一，
// 内嵌环境还可能直接拦截。
func TestNoNativeBrowserDialogs(t *testing.T) {
	entries, err := assets.ReadDir("templates")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".html") {
			continue
		}
		raw, err := assets.ReadFile("templates/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		checked++
		if loc := nativeDialogCall.FindStringIndex(string(raw)); loc != nil {
			line := 1 + strings.Count(string(raw)[:loc[0]], "\n")
			t.Fatalf("templates/%s:%d 仍在使用浏览器原生弹窗，请改用 appConfirm/appPrompt/appWhitelistDialog", entry.Name(), line)
		}
	}
	if checked == 0 {
		t.Fatal("未找到任何模板文件")
	}

	appJS, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(appJS)
	for _, want := range []string{
		"function appFormDialog(", "function appConfirm(", "function appPrompt(", "function appWhitelistDialog(",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("app.js 缺少统一弹窗助手 %q", want)
		}
	}
	if loc := nativeDialogCall.FindStringIndex(src); loc != nil {
		t.Fatalf("app.js 仍在使用浏览器原生弹窗: %s", src[loc[0]:loc[1]])
	}
}

// TestDialogPagesUseAppHelpers 确保原先使用原生弹窗的页面都已接入应用内弹窗助手，
// 防止后续改动把 confirm/prompt 又加回来。
func TestDialogPagesUseAppHelpers(t *testing.T) {
	pages := map[string][]string{
		"templates/scan_detail.html":     {"appConfirm("},
		"templates/tasks.html":           {"appConfirm("},
		"templates/scans.html":           {"appConfirm("},
		"templates/assets.html":          {"appConfirm("},
		"templates/alerts.html":          {"appConfirm(", "appFormDialog("},
		"templates/whitelist.html":       {"appConfirm("},
		"templates/accounts.html":        {"appConfirm(", "appPrompt("},
		"templates/domain_detail.html":   {"appConfirm("},
		"templates/analysis.html":        {"appConfirm("},
		"templates/analysis_detail.html": {"appConfirm(", "appWhitelistDialog("},
	}
	for name, wants := range pages {
		raw, err := assets.ReadFile(name)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", name, err)
		}
		for _, want := range wants {
			if !strings.Contains(string(raw), want) {
				t.Fatalf("%s 未接入 %s", name, want)
			}
		}
	}
}
