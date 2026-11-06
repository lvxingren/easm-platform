package engine

import (
	"strings"
	"testing"
)

func TestClassifyTargetSupportsDomain(t *testing.T) {
	valid := map[string]string{
		"1.2.3.4":           "ip",
		"10.0.0.0/24":       "cidr",
		"1.2.3.1-1.2.3.50":  "range",
		"example.com":       "domain",
		"sub.example.co.uk": "domain",
		"*.example.com":     "domain",
		"a-b.example.com":   "domain",
	}
	for in, want := range valid {
		kind, ok := ClassifyTarget(in)
		if !ok || kind != want {
			t.Fatalf("ClassifyTarget(%q)=%q,%v，期望 %q,true", in, kind, ok, want)
		}
	}
	invalid := []string{
		"", "not a domain", "http://example.com", "example.com/path", "example.com:8080",
		"-bad.com", "bad-.com", "example.", "localhost", "1.2.3.4.5.6.7.8.9.0", "exa mple.com",
	}
	for _, in := range invalid {
		if kind, ok := ClassifyTarget(in); ok {
			t.Fatalf("ClassifyTarget(%q) 应非法，却得到 %q", in, kind)
		}
	}
}

func TestValidDomainBoundaries(t *testing.T) {
	if ValidDomain("1.2.3.4") {
		t.Fatal("纯 IP 不应被判为域名（应由 parseTargetMatcher 先处理）")
	}
	if !ValidDomain("EXAMPLE.com") {
		t.Fatal("域名应大小写不敏感")
	}
	if ValidDomain("a." + strings.Repeat("b", 260)) {
		t.Fatal("超长域名应非法")
	}
}
