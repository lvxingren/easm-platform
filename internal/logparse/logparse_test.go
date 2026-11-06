package logparse

import "testing"

func TestParseCSVWithHeaderAndAggregate(t *testing.T) {
	data := "src_ip,dst_ip,dst_port,protocol,action,timestamp\n" +
		"10.0.0.5,1.2.3.4,443,tcp,allow,2026-11-06T10:00:00Z\n" +
		"10.0.0.5,1.2.3.4,443,tcp,allow,2026-11-06T10:01:00Z\n" +
		"10.0.0.6,10.0.0.5,22,tcp,allow,2026-11-06T10:02:00Z\n" +
		"bad,row,only\n"
	res, err := ParseBytes([]byte(data), "cfw.csv")
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "csv" {
		t.Fatalf("format=%s", res.Format)
	}
	if len(res.Flows) != 3 {
		t.Fatalf("flows=%d，期望 3：%+v", len(res.Flows), res.Flows)
	}
	edges := Aggregate(res.Flows)
	found := false
	for _, e := range edges {
		if e.SrcIP == "10.0.0.5" && e.DstIP == "1.2.3.4" && e.DstPort == 443 {
			found = true
			if e.Count != 2 {
				t.Fatalf("聚合次数=%d，期望 2", e.Count)
			}
			if e.FirstSeen != "2026-11-06T10:00:00Z" || e.LastSeen != "2026-11-06T10:01:00Z" {
				t.Fatalf("时间聚合错误：%+v", e)
			}
		}
	}
	if !found {
		t.Fatalf("未正确聚合：%+v", edges)
	}
	if edges[0].Count < edges[len(edges)-1].Count {
		t.Fatal("聚合结果应按次数降序")
	}
}

func TestParseJSONWithChineseHeaders(t *testing.T) {
	data := `[{"源IP":"10.0.0.1","目的IP":"8.8.8.8","目的端口":53,"协议":"udp","动作":"allow","时间":"2026-11-06T09:00:00Z"}]`
	res, err := ParseBytes([]byte(data), "ecs.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Flows) != 1 {
		t.Fatalf("flows=%d，期望 1", len(res.Flows))
	}
	f := res.Flows[0]
	if f.SrcIP != "10.0.0.1" || f.DstIP != "8.8.8.8" || f.DstPort != 53 || f.Proto != "udp" {
		t.Fatalf("中文字段解析错误：%+v", f)
	}
}

func TestParseNDJSONAndDomain(t *testing.T) {
	data := "{\"src_ip\":\"10.0.0.2\",\"dst_ip\":\"example.com\",\"dst_port\":443,\"protocol\":\"tcp\"}\n" +
		"{\"src_ip\":\"10.0.0.3\",\"dst_ip\":\"bad.example\",\"dst_port\":80,\"protocol\":\"tcp\"}\n"
	res, err := ParseBytes([]byte(data), "flow.log")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Flows) != 2 {
		t.Fatalf("NDJSON flows=%d，期望 2", len(res.Flows))
	}
	if res.Flows[0].DstIP != "example.com" {
		t.Fatalf("域名目的地址未保留：%+v", res.Flows[0])
	}
}

func TestNormalizeHelpers(t *testing.T) {
	if p := parsePort("443"); p != 443 {
		t.Fatalf("parsePort(443)=%d", p)
	}
	if p := parsePort("80-90"); p != 80 {
		t.Fatalf("parsePort(80-90)=%d", p)
	}
	if p := parsePort("abc"); p != 0 {
		t.Fatalf("parsePort(abc)=%d", p)
	}
	if normalizeProto("6") != "tcp" || normalizeProto("17") != "udp" || normalizeProto("TCP") != "tcp" {
		t.Fatal("协议归一化错误")
	}
}
