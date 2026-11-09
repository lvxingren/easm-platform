package engine

import (
	"path/filepath"
	"strings"
	"testing"

	"easm-platform/internal/config"
	"easm-platform/internal/store"
)

func newFscanEngine(t *testing.T) (*Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, &config.Config{}), st
}

func TestAppendFscanSections(t *testing.T) {
	e, st := newFscanEngine(t)
	scanID, _ := st.CreateScan(0, "fscan", "top")

	// 无 engine=fscan 事件：原样返回（naabu 兼容）。
	if got := e.appendFscanSections("base", scanID); got != "base" {
		t.Fatalf("非 fscan 应原样返回: %q", got)
	}

	_ = st.AddScanEvent(scanID, "info", "engine", "fscan")
	_ = st.InsertResults(scanID, []store.Result{{IP: "192.0.2.1", Port: 445, Proto: "tcp", Service: "SMB", Status: 1}})
	_, _ = st.InsertVulns(scanID, []store.VulnRecord{{IP: "192.0.2.1", Port: 445, Vuln: "SMBGhost", Severity: "high"}})

	got := e.appendFscanSections("base", scanID)
	if !strings.Contains(got, "端口发现：共 1 个开放端口") || !strings.Contains(got, "192.0.2.1:445") {
		t.Fatalf("应追加端口清单: %q", got)
	}
	if !strings.Contains(got, "漏洞发现：高危 1 条") || !strings.Contains(got, "SMBGhost") {
		t.Fatalf("应追加漏洞清单: %q", got)
	}
}

func TestAppendPortSectionEmpty(t *testing.T) {
	e, st := newFscanEngine(t)
	scanID, _ := st.CreateScan(0, "empty", "top")
	if got := e.appendPortSection("base", scanID); got != "base" {
		t.Fatalf("无结果应原样返回: %q", got)
	}
}
