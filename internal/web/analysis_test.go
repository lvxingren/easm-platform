package web

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const sampleCFWCSV = "src_ip,dst_ip,dst_port,protocol,action,timestamp\n" +
	"10.0.0.5,10.0.0.9,3389,tcp,allow,2026-11-06T10:00:00Z\n" +
	"10.0.0.5,1.2.3.4,443,tcp,allow,2026-11-06T10:01:00Z\n" +
	"10.0.0.6,10.0.0.9,3389,tcp,allow,2026-11-06T10:02:00Z\n"

func analysisUploadReq(user, name, filename, content string) *http.Request {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("name", name)
	_ = mw.WriteField("source_type", "cfw")
	fw, _ := mw.CreateFormFile("files", filename)
	_, _ = fw.Write([]byte(content))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/analysis", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "easm_sid", Value: "test-" + user})
	return req
}

func waitAnalysisDone(t *testing.T, server *Server, id int64) map[string]interface{} {
	t.Helper()
	for i := 0; i < 200; i++ {
		rec := scanLiveRequest(server, http.MethodGet, "/api/analysis/"+strconv.FormatInt(id, 10), "operator")
		var d map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		switch d["status"] {
		case "done":
			return d
		case "failed":
			t.Fatalf("分析失败: %v", d["error"])
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("等待分析完成超时")
	return nil
}

func TestAnalysisPipelineRuleBasedAndRBAC(t *testing.T) {
	t.Chdir(t.TempDir())
	server, st := newScanLiveTestServer(t)

	// viewer 不能创建分析
	vrec := httptest.NewRecorder()
	server.Handler().ServeHTTP(vrec, analysisUploadReq("viewer", "x", "a.csv", sampleCFWCSV))
	if vrec.Code != http.StatusForbidden {
		t.Fatalf("viewer 创建分析应 403，实际 %d", vrec.Code)
	}

	// operator 创建并等待完成（无 AI 端点 → 内置规则降级）
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, analysisUploadReq("operator", "CFW 测试", "cfw.csv", sampleCFWCSV))
	if rec.Code != http.StatusOK {
		t.Fatalf("创建分析状态=%d 响应=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	id := created.ID
	d := waitAnalysisDone(t, server, id)
	if usedMock, _ := d["used_mock"].(bool); !usedMock {
		t.Fatal("未配置 AI 端点应标记 used_mock")
	}
	if fc, _ := d["flow_count"].(float64); fc != 3 {
		t.Fatalf("原始记录数=%v，期望 3", d["flow_count"])
	}
	if ec, _ := d["edge_count"].(float64); ec == 0 {
		t.Fatalf("聚合通信关系为 0：%v", d["edge_count"])
	}
	if d["topology"] == nil {
		t.Fatal("topology 结果缺失")
	}

	// 落库校验
	a, _ := st.Analysis(id)
	if a == nil || a.Status != "done" || !a.UsedMock || a.EdgeCount == 0 {
		t.Fatalf("分析落库错误：%+v", a)
	}
	if edges, _ := st.AnalysisEdges(id, 0); len(edges) == 0 {
		t.Fatal("通信关系未落库")
	}
	if files, _ := st.AnalysisFiles(id); len(files) != 1 || files[0].Filename != "cfw.csv" {
		t.Fatalf("文件记录错误：%+v", files)
	}

	// 列表页与详情页渲染
	if list := scanLiveRequest(server, http.MethodGet, "/analysis", "operator"); list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "CFW 测试") {
		t.Fatalf("分析列表页渲染异常：%d", list.Code)
	}
	if detail := scanLiveRequest(server, http.MethodGet, "/analysis/"+strconv.FormatInt(id, 10), "operator"); detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), "网络拓扑关系图") {
		t.Fatalf("分析详情页渲染异常：%d", detail.Code)
	}

	// 从分析结果一键建告警
	alertForm := url.Values{}
	alertForm.Set("ip", "10.0.0.9")
	alertForm.Set("port", "3389")
	alertForm.Set("proto", "tcp")
	alertForm.Set("note", "来自流量分析")
	if r2 := scanFormRequest(server, "/api/alerts/manual", "operator", alertForm); r2.Code != http.StatusOK {
		t.Fatalf("建告警状态=%d 响应=%s", r2.Code, r2.Body.String())
	}
	if alerts, _ := st.AlertsFiltered("", "", 0); len(alerts) != 1 {
		t.Fatalf("告警未创建：%+v", alerts)
	}
	if r2 := scanFormRequest(server, "/api/alerts/manual", "viewer", alertForm); r2.Code != http.StatusForbidden {
		t.Fatalf("viewer 建告警应 403，实际 %d", r2.Code)
	}
	// 非法端口应 400
	badForm := url.Values{}
	badForm.Set("ip", "10.0.0.9")
	badForm.Set("port", "0")
	if r2 := scanFormRequest(server, "/api/alerts/manual", "operator", badForm); r2.Code != http.StatusBadRequest {
		t.Fatalf("非法端口建告警应 400，实际 %d", r2.Code)
	}

	// 删除分析（含磁盘文件清理）
	if r2 := scanLiveRequest(server, http.MethodDelete, "/api/analysis/"+strconv.FormatInt(id, 10), "operator"); r2.Code != http.StatusOK {
		t.Fatalf("删除分析状态=%d", r2.Code)
	}
	if a2, _ := st.Analysis(id); a2 != nil {
		t.Fatal("删除后分析记录仍存在")
	}
}
