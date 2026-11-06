package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalFindingsDetectsEncodedPayloadsAndPreservesBusiness(t *testing.T) {
	for _, fixture := range []struct{ name, text, category string }{
		{"SQL union", `{"q":"union/**/select 1"}`, "sql_injection"},
		{"SQL delay", `x=1 and sleep(5)`, "sql_injection"},
		{"SQL quote", `x=' or 1=1--`, "sql_injection"},
		{"RCE", `cmd.exe /c whoami`, "command"},
		{"Java RCE", `Runtime.getRuntime().exec("x")`, "command"},
		{"backdoor command", `{"methodName":"execCommand"}`, "command"},
		{"traversal", `{"file":"..\\..\\secret"}`, "path_traversal"},
		{"double URL", `file=%252e%252e%255c%252e%252e%255csecret`, "path_traversal"},
		{"malformed percent", `x=%GG&file=%252e%252e%252f%252e%252e%252fsecret`, "path_traversal"},
		{"JSON escapes", `{"q":"\u0075nion\u0020select 1"}`, "sql_injection"},
		{"JNDI", `${jndi:ldap://example.invalid/x}`, "jndi"},
		{"JNDI letters", `${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://example.invalid/x}`, "jndi"},
		{"JSP", `<%@ page import="java.lang.*" %>`, "jsp_source"},
		{"PHP", `<?php system($_GET['x']); ?>`, "php_source"},
		{"YQ short", `{"sys_track_code":"YQ_SQ_38939"}`, "invalid_yq_track_code"},
		{"YQ too long", `{"sys_track_code":"YQ_17938030009892789_01"}`, "invalid_yq_track_code"},
		{"YQ form", `sys_track_code=YQ_123_01`, "invalid_yq_track_code"},
		{"valid YQ", `{"sys_track_code":"YQ_1793803000989278_01"}`, ""},
		{"UUID", `{"sys_track_code":"59abbeee-85f1-4c3c-9914-7b791b79e001"}`, ""},
		{"ordinary business", `{"method":"downloadFile","name":"normal.pdf","q":"doctor and nurse"}`, ""},
		{"payment XML XSS disabled", `<xml><return_code><![CDATA[SUCCESS]]></return_code><note>onerror=</note></xml>`, ""},
		{"script XSS disabled", `<script>alert(1)</script>`, ""},
		{"plain powershell mention", `documentation about powershell`, ""},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			findings := localFindings(Entry{Body: fixture.text, Decoded: Decoded{State: "plain"}})
			if fixture.category == "" {
				if len(findings) != 0 {
					t.Fatalf("ordinary request was flagged: %+v", findings)
				}
				return
			}
			for _, finding := range findings {
				if finding.Category == fixture.category && finding.Rule != "" && finding.Source != "" {
					return
				}
			}
			t.Fatalf("missing %s: %+v", fixture.category, findings)
		})
	}
	for _, uri := range []string{"/.env", "/.git/HEAD", "/actuator/heapdump", "/WEB-INF/web.xml", "/etc/passwd"} {
		if findings := localFindings(Entry{URI: uri}); len(findings) == 0 || findings[0].Category != "sensitive_file" {
			t.Fatalf("sensitive file not found: %s", uri)
		}
	}
}

func TestLocalRulesBoundsAndDisclosure(t *testing.T) {
	entry := Entry{Body: strings.Repeat("a", localScanLimit) + "union select 1", Decoded: Decoded{State: "partial", Unresolved: 2}}
	if len(localFindings(entry)) != 0 {
		t.Fatal("scanner exceeded its bounded input")
	}
	report := localReview([]Entry{entry})
	for _, required := range []string{"无命中不代表安全", "前 128 KiB", "2 个字段", "partial", "不自动封禁", "XSS 规则当前不启用"} {
		if !strings.Contains(report, required) {
			t.Fatalf("report did not disclose %q", required)
		}
	}
}

func TestLocalAnalysisNeverCallsModelAndNeedsNoCredential(t *testing.T) {
	calls := 0
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(500)
	}))
	defer model.Close()
	store, err := openStore(filepath.Join(t.TempDir(), "local.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	entries := []Entry{{Body: `union select 1`, Decoded: Decoded{State: "plain"}, AIReport: "old-ai-report"}, {Decoded: Decoded{State: "encrypted"}}}
	if err := store.commit("fixture", ReadCursor{}, entries); err != nil {
		t.Fatal(err)
	}
	config := fixtureConfig("http://127.0.0.1:1")
	config.AnalysisMode = "local"
	config.AI = AIConfig{model.URL, "fixture-key", "test-model"}
	app := &App{config: config, store: store, collector: newCollector(config, store)}
	for _, creds := range []bool{true, false} {
		if !creds {
			app.config.AI = AIConfig{}
		}
		analyzeFixture(t, app, "/api/analyze", `{"ids":[1,2]}`, 200)
		entry, err := store.entry(1)
		if err != nil || !strings.Contains(entry.LocalReport, "SQL-001") || !strings.Contains(entry.LocalReport, "encrypted") || entry.AIReport != "old-ai-report" {
			t.Fatal("local report missing or old AI report overwritten")
		}
	}
	if calls != 0 {
		t.Fatalf("local analysis called the model %d times", calls)
	}
	w := httptest.NewRecorder()
	app.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8790/api/status", nil))
	var status struct {
		Mode         string `json:"analysis_mode"`
		Available    bool   `json:"analysis_available"`
		AIConfigured bool   `json:"ai_configured"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil || status.Mode != "local" || !status.Available || status.AIConfigured {
		t.Fatal("local status requires a model or presents AI as active")
	}
}

func TestOldEntriesUseCurrentLocalRulesWithoutReprocessing(t *testing.T) {
	store, err := openStore(filepath.Join(t.TempDir(), "old.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	entries := []Entry{
		{Body: `<script>example</script>`, Findings: []Finding{{Category: "xss", Description: "old rule"}}, Decoded: Decoded{State: "plain"}},
		{Body: `{"sys_track_code":"YQ_SQ_38939"}`, Decoded: Decoded{State: "plain"}},
	}
	if err := store.commit("fixture", ReadCursor{}, entries); err != nil {
		t.Fatal(err)
	}
	page, err := store.list(Query{Suspicious: true, Limit: 100})
	if err != nil || len(page.Entries) != 1 || page.Entries[0].ID != 2 {
		t.Fatal("old rules were reused or old records were not inspected")
	}
	entry, err := store.entry(1)
	if err != nil || len(entry.Findings) != 0 || entry.Body != entries[0].Body || entry.AIRevision != 0 {
		t.Fatal("reading old records changed decoding or retained disabled XSS")
	}
}

func TestLocalModeLoadsFromLivelogEnvironment(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "livelog.env")
	if err := os.WriteFile(envPath, []byte("PANEL_URL=http://127.0.0.1:1\nPANEL_API_KEY=fixture\nAI_ANALYSIS_MODE=local\nDEEPSEEK_API_KEY=fixture\nDEEPSEEK_BASE_URL=invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"livelog_env":"livelog.env"}`), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := loadConfig(configPath)
	if err != nil || config.AnalysisMode != "local" {
		t.Fatalf("local configuration still required valid AI credentials: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`{"livelog_env":"livelog.env","analysis_mode":"ai"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if config, err := loadConfig(configPath); err != nil || config.AnalysisMode != "local" {
		t.Fatal("old per-app AI setting bypassed the shared local-only setting")
	}
}

func TestLocalDefenseRejectsAIOrAutomaticBlockingController(t *testing.T) {
	mode, autoBlock, ingested := "ai", false, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/ai":
			_ = json.NewEncoder(w).Encode(map[string]any{"settings": map[string]any{"analysisMode": mode, "autoBlock": autoBlock, "enabled": true}})
		case "/api/af":
			_, _ = w.Write([]byte(`{"settings":{"enabled":false},"status":{}}`))
		case "/v1/ingest":
			ingested++
			_, _ = w.Write([]byte(`{"accepted":1}`))
		case "/v1/verdicts":
			_, _ = w.Write([]byte(`{"events":[]}`))
		default:
			t.Error("unexpected request: " + r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	store, err := openStore(filepath.Join(t.TempDir(), "defense-local.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	if err := store.commit("fixture", ReadCursor{}, []Entry{{URI: "/api", Decoded: Decoded{State: "plain"}}}); err != nil {
		t.Fatal(err)
	}
	config := Config{AnalysisMode: "local", Defense: DefenseConfig{Enabled: true, HubURL: server.URL, LivelogURL: server.URL}}
	d := newDefense(config, store)
	if _, err := d.once(context.Background()); err == nil || ingested != 0 {
		t.Fatal("local worker submitted to an AI controller")
	}
	mode, autoBlock, d.controllerAt = "local", true, time.Time{}
	if _, err := d.once(context.Background()); err == nil || ingested != 0 {
		t.Fatal("local worker submitted with automatic blocking enabled")
	}
	autoBlock, d.controllerAt = false, time.Time{}
	if n, err := d.once(context.Background()); err != nil || n != 1 || ingested != 1 || d.status().AnalysisMode != "local" {
		t.Fatalf("manual local controller did not receive the queued record: %v", err)
	}
}

func BenchmarkLocalRulesBusiness(b *testing.B) {
	text := `{"head":{"method":"orgine.poweruap.api.proxy.core.proxy","sys_track_code":"YQ_1793803000989278_01","timestamp":1793803000989},"body":{"method_code":"getBusinessList","page":1,"page_size":20,"status":"SUCCESS","items":[]}}`
	entry := Entry{URI: "/orgine-poweruap-api-proxy/gateway", Body: text, Decoded: Decoded{State: "plain", Text: text}}
	for b.Loop() {
		localFindings(entry)
	}
}

func TestLovelyLogLocalConfigStaysLocalWhileSharedEnvironmentUsesAI(t *testing.T) {
	modelCalls := 0
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modelCalls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer model.Close()
	dir := t.TempDir()
	env := strings.Join([]string{"PANEL_URL=http://127.0.0.1:1", "PANEL_API_KEY=fixture", "AI_ANALYSIS_MODE=ai", "DEEPSEEK_BASE_URL=" + model.URL, "DEEPSEEK_API_KEY=fixture", "DEEPSEEK_MODEL=fixture-model"}, "\n")
	envPath := filepath.Join(dir, "livelog.env")
	if err := os.WriteFile(envPath, []byte(env), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"livelog_env":"livelog.env","analysis_mode":"local"}`), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := loadConfig(configPath)
	if err != nil || config.AnalysisMode != "local" {
		t.Fatalf("shared AI setting overrode LovelyLog local mode: %v", err)
	}
	store, err := openStore(config.DataFile)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	if err := store.commit("fixture", ReadCursor{}, []Entry{{Body: "union select 1", Decoded: Decoded{State: "plain"}}}); err != nil {
		t.Fatal(err)
	}
	app := &App{config: config, store: store}
	analyzeFixture(t, app, "/api/analyze", `{"ids":[1]}`, 200)
	if modelCalls != 0 {
		t.Fatal("LovelyLog used the platform AI credentials in local mode")
	}
	if data, err := os.ReadFile(envPath); err != nil || string(data) != env {
		t.Fatal("LovelyLog changed the shared platform environment")
	}
	if err := os.WriteFile(configPath, []byte(`{"livelog_env":"livelog.env"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if globalConfig, err := loadConfig(configPath); err != nil || globalConfig.AnalysisMode != "ai" {
		t.Fatal("the unchanged shared setting no longer enables AI for other configurations")
	}
}

func TestAgentScopedLocalDefenseAllowsPlatformAIAndAutomaticBlocking(t *testing.T) {
	const agentID = "11111111-1111-1111-1111-111111111111"
	ingested := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/ai":
			if r.URL.Query().Get("source") != "agent" || r.URL.Query().Get("agent") != agentID {
				t.Error("controller queried global settings instead of the LovelyLog agent scope")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"settings": map[string]any{"analysisMode": "local", "autoBlock": false, "enabled": true, "analysisScope": "agent", "scopedAgentId": agentID, "platformAnalysisMode": "ai", "platformAutoBlock": true}})
		case "/api/af":
			_, _ = w.Write([]byte(`{"settings":{"enabled":true},"status":{}}`))
		case "/v1/ingest":
			ingested++
			_, _ = w.Write([]byte(`{"accepted":1}`))
		case "/v1/verdicts":
			_, _ = w.Write([]byte(`{"events":[]}`))
		default:
			t.Error("unexpected request: " + r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	store, err := openStore(filepath.Join(t.TempDir(), "scoped-local.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	if err := store.commit("fixture", ReadCursor{}, []Entry{{URI: "/api", Decoded: Decoded{State: "plain"}}}); err != nil {
		t.Fatal(err)
	}
	config := Config{AnalysisMode: "local", Defense: DefenseConfig{Enabled: true, HubURL: server.URL, LivelogURL: server.URL, AgentID: agentID, Token: "fixture-agent-token"}}
	d := newDefense(config, store)
	if n, err := d.once(context.Background()); err != nil || n != 1 || ingested != 1 {
		t.Fatalf("agent-local delivery incorrectly required the platform AI to stop: %v", err)
	}
	status := d.status()
	if status.AnalysisMode != "local" || status.AnalysisScope != "agent" || status.PlatformAnalysisMode != "ai" || !status.PlatformAutoBlock || status.AutoBlock || status.AIEnabled {
		t.Fatalf("platform and agent settings were conflated: %+v", status)
	}
}
