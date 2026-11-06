package ai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"easm-platform/internal/logparse"
)

func TestRuleBasedWhenNoEndpoint(t *testing.T) {
	edges := []logparse.Edge{
		{SrcIP: "10.0.0.5", DstIP: "10.0.0.9", DstPort: 3389, Proto: "tcp", Count: 5},
		{SrcIP: "10.0.0.5", DstIP: "1.2.3.4", DstPort: 443, Proto: "tcp", Count: 2},
	}
	rep, usedMock, err := Analyze(Config{}, edges, 7, "cfw")
	if err != nil {
		t.Fatal(err)
	}
	if !usedMock {
		t.Fatal("未配置端点应使用内置规则降级")
	}
	if len(rep.Nodes) == 0 || len(rep.Edges) == 0 {
		t.Fatalf("降级应产出节点与边：%+v", rep)
	}
	hasHigh := false
	for _, a := range rep.Anomalies {
		if a.Severity == "high" {
			hasHigh = true
		}
	}
	if !hasHigh {
		t.Fatalf("高危端口 3389 应产生 high 异常：%+v", rep.Anomalies)
	}
	if rep.Readable == "" || rep.TopologySummary == "" {
		t.Fatal("降级应产出摘要与可读报告")
	}
}

func TestValidateEndpoint(t *testing.T) {
	if err := ValidateEndpoint("https://api.example.com/v1"); err != nil {
		t.Fatalf("https 应通过: %v", err)
	}
	if err := ValidateEndpoint("http://localhost:8080/v1"); err != nil {
		t.Fatalf("本地 http 应允许: %v", err)
	}
	if err := ValidateEndpoint("http://api.example.com/v1"); err == nil {
		t.Fatal("非本地 http 应拒绝")
	}
	if err := ValidateEndpoint(""); err == nil {
		t.Fatal("空端点应拒绝")
	}
	if err := ValidateEndpoint("不是URL"); err == nil {
		t.Fatal("非法 URL 应拒绝")
	}
}

func TestExtractJSON(t *testing.T) {
	if got := extractJSON("```json\n{\"a\":1}\n```"); got != "{\"a\":1}" {
		t.Fatalf("got %q", got)
	}
	if got := extractJSON("分析如下 {\"a\":1} 以上"); got != "{\"a\":1}" {
		t.Fatalf("got %q", got)
	}
}

func TestCallOpenAICompatible(t *testing.T) {
	want := Report{TopologySummary: "拓扑摘要", Nodes: []Node{{IP: "10.0.0.1", Role: "服务器"}}, Readable: "可读报告"}
	content, _ := json.Marshal(want)
	var gotAuth, gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var reqBody struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&reqBody)
		gotModel = reqBody.Model
		resp := map[string]interface{}{
			"choices": []map[string]interface{}{{"message": map[string]string{"content": string(content)}}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	cfg := Config{Endpoint: srv.URL + "/v1", APIKey: "sk-test", Model: "test-model", TimeoutSec: 5}
	edges := []logparse.Edge{{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 443, Proto: "tcp", Count: 1}}
	rep, usedMock, err := Analyze(cfg, edges, 1, "cfw")
	if err != nil {
		t.Fatalf("OpenAI 兼容调用失败: %v", err)
	}
	if usedMock {
		t.Fatal("配置端点后不应走降级")
	}
	if rep.TopologySummary != "拓扑摘要" || rep.Readable != "可读报告" || len(rep.Nodes) != 1 {
		t.Fatalf("解析 AI 响应错误：%+v", rep)
	}
	if !strings.HasPrefix(gotAuth, "Bearer sk-test") {
		t.Fatalf("未正确发送 Bearer Token：%q", gotAuth)
	}
	if gotModel != "test-model" {
		t.Fatalf("未正确发送模型名：%q", gotModel)
	}
}

func TestCallOpenAIErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("invalid api key"))
	}))
	defer srv.Close()
	cfg := Config{Endpoint: srv.URL, APIKey: "bad", Model: "m", TimeoutSec: 5}
	if _, _, err := Analyze(cfg, nil, 0, "cfw"); err == nil {
		t.Fatal("鉴权失败应返回 error")
	}
}
