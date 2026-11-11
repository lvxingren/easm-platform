package store

import (
	"path/filepath"
	"testing"
)

func TestSetScanUDPEnabledAndRead(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "udp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, _ := st.CreateScan(0, "udp", "top")
	if err := st.SetScanUDPEnabled(id, true); err != nil {
		t.Fatal(err)
	}
	sc, _ := st.Scan(id)
	if !sc.UDPEnabled {
		t.Fatal("UDPEnabled 应为 true")
	}
	_ = st.SetScanUDPEnabled(id, false)
	sc, _ = st.Scan(id)
	if sc.UDPEnabled {
		t.Fatal("UDPEnabled 应为 false")
	}
}

func TestTaskUDPRoundTrip(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "taskudp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, err := st.CreateScanTask(ScanTask{Name: "proto-task", Mode: "top", Engine: "naabu", Protocol: "both", TargetType: "all"})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := st.ScanTask(id)
	if got.Protocol != "both" || !got.WantsUDP() || !got.WantsTCP() {
		t.Fatalf("任务协议应持久化为 both: %+v", got)
	}
	got.Protocol = "udp"
	if err := st.UpdateScanTask(*got); err != nil {
		t.Fatal(err)
	}
	got2, _ := st.ScanTask(id)
	if got2.Protocol != "udp" || !got2.WantsUDP() || got2.WantsTCP() {
		t.Fatalf("更新后协议应为 udp（仅 UDP）: %+v", got2)
	}
	got2.Protocol = "tcp"
	if err := st.UpdateScanTask(*got2); err != nil {
		t.Fatal(err)
	}
	got3, _ := st.ScanTask(id)
	if got3.Protocol != "tcp" || got3.WantsUDP() || !got3.WantsTCP() {
		t.Fatalf("更新后协议应为 tcp（纯 TCP）: %+v", got3)
	}
}

func TestOpenPortsByIPs(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "open.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, _ := st.CreateScan(0, "s", "top")
	_ = st.InsertResults(id, []Result{
		{IP: "192.0.2.1", Port: 80, Proto: "tcp", Status: 1},
		{IP: "192.0.2.1", Port: 443, Proto: "tcp", Status: 1},
		{IP: "192.0.2.1", Port: 53, Proto: "udp", Status: 1},
		{IP: "192.0.2.2", Port: 22, Proto: "tcp", Status: 1},
		{IP: "192.0.2.3", Port: 99, Proto: "tcp", Status: 0}, // 非开放，排除
	})
	open, err := st.OpenPortsByIPs([]string{"192.0.2.1", "192.0.2.1", "192.0.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 3 { // 80/443/53，去重 IP，排除 status0
		t.Fatalf("应 3 条开放端口: %+v", open)
	}
	if n, _ := st.OpenPortsByIPs(nil); n != nil {
		t.Fatal("空输入应 nil")
	}
}

func TestWhitelistSourceRoundTrip(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "wl.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.AddWhitelist(WLEntry{IPSpec: "192.0.2.1", PortSpec: "80", Proto: "tcp", Source: "auto_match"}); err != nil {
		t.Fatal(err)
	}
	entries, _ := st.Whitelist()
	if len(entries) != 1 || entries[0].Source != "auto_match" {
		t.Fatalf("source 应持久化: %+v", entries)
	}
}
