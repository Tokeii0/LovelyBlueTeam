package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func analyzeFixture(t *testing.T, app *App, path, ids string, status int) bool {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8790"+path, strings.NewReader(ids))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != status {
		t.Fatalf("%s returned %d: %s", path, w.Code, w.Body.String())
	}
	var result struct {
		Cached bool `json:"cached"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result.Cached
}

func TestManualAnalysisCachePersistsAndSeparatesBatches(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"本地测试报告"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()
	path := filepath.Join(t.TempDir(), "cache.db")
	store, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.db.Close() }()
	entry := makeEntry(`{"time":"2026-11-05T10:00:00+08:00","ip":"8.8.8.8","method":"POST","uri":"/api","body":"{\"query\":\"union select 1\"}","status":"403"}`, nil)
	if err := store.commit("fixture", ReadCursor{}, []Entry{entry, entry}); err != nil {
		t.Fatal(err)
	}
	config := fixtureConfig("http://127.0.0.1:1")
	config.AI = AIConfig{upstream.URL, "fixture-key", "test-model"}
	app := &App{config: config, store: store}
	if analyzeFixture(t, app, "/api/analyze", `{"ids":[1]}`, 200) || calls != 1 {
		t.Fatal("first analysis did not call the model exactly once")
	}
	if !analyzeFixture(t, app, "/api/analyze", `{"ids":[1,1]}`, 200) || calls != 1 {
		t.Fatal("repeated click called the model")
	}
	if analyzeFixture(t, app, "/api/analyze", `{"ids":[1,2]}`, 200) || calls != 2 {
		t.Fatal("different batch reused an unrelated report")
	}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	app = &App{config: config, store: store}
	if !analyzeFixture(t, app, "/api/analyze", `{"ids":[1]}`, 200) || calls != 2 {
		t.Fatal("cache did not survive reopening the database")
	}
	analyzeFixture(t, app, "/api/redecode", `{"ids":[1]}`, 200)
	reparsed, err := store.entry(1)
	if err != nil || reparsed.AIRevision != 1 || reparsed.AIReport != "" {
		t.Fatal("redecode did not invalidate the stored analysis")
	}
	if analyzeFixture(t, app, "/api/analyze", `{"ids":[1]}`, 200) || calls != 3 {
		t.Fatal("redecode reused a report from the previous parsing revision")
	}
	if _, err := reprocess(store, nil); err != nil {
		t.Fatal(err)
	}
	if analyzeFixture(t, app, "/api/analyze", `{"ids":[1]}`, 200) || calls != 4 {
		t.Fatal("bulk reprocessing did not invalidate the cache")
	}
	app.config.AI.Model = "different-model"
	if analyzeFixture(t, app, "/api/analyze", `{"ids":[1]}`, 200) || calls != 5 {
		t.Fatal("changing the model reused an old report")
	}
}

func TestManualAnalysisErrorsAreNotCached(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(429)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"成功报告"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()
	store, err := openStore(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	if err := store.commit("fixture", ReadCursor{}, []Entry{{URI: "/a", Decoded: Decoded{State: "plain"}}}); err != nil {
		t.Fatal(err)
	}
	config := fixtureConfig("http://127.0.0.1:1")
	config.AI = AIConfig{upstream.URL, "fixture-key", "test-model"}
	app := &App{config: config, store: store}
	analyzeFixture(t, app, "/api/analyze", `{"ids":[1]}`, 502)
	analyzeFixture(t, app, "/api/analyze", `{"ids":[1]}`, 502)
	if analyzeFixture(t, app, "/api/analyze", `{"ids":[1]}`, 200) || calls != 3 {
		t.Fatal("failure was cached")
	}
	if !analyzeFixture(t, app, "/api/analyze", `{"ids":[1]}`, 200) || calls != 3 {
		t.Fatal("successful retry was not cached")
	}
}

func TestAnalysisCacheUsesExactPreparedRequestAndConfiguration(t *testing.T) {
	config := AIConfig{"https://model.example/v1", "fixture-key", "test-model"}
	entries := []Entry{{ID: 1, URI: "/api", IP: "8.8.8.8", Decoded: Decoded{State: "plain", Text: `{"query":"first"}`}}}
	endpoint, body, err := analysisRequest(config, entries)
	if err != nil {
		t.Fatal(err)
	}
	key := analysisCacheKey(endpoint, config.Key, body, entries)
	if strings.Contains(key, config.Key) || len(key) != 64 {
		t.Fatal("cache key leaked the credential or is not a SHA-256")
	}
	for _, field := range []string{"body", "state", "unresolved", "ip", "model", "endpoint", "credential", "prompt", "revision"} {
		t.Run(field, func(t *testing.T) {
			changedEntries := append([]Entry(nil), entries...)
			changedConfig := config
			switch field {
			case "body":
				changedEntries[0].Decoded.Text = `{"query":"second"}`
			case "state":
				changedEntries[0].Decoded.State = "partial"
			case "unresolved":
				changedEntries[0].Decoded.Unresolved++
			case "ip":
				changedEntries[0].IP = "8.8.4.4"
			case "model":
				changedConfig.Model = "other-model"
			case "endpoint":
				changedConfig.BaseURL = "https://different.example/v1"
			case "credential":
				changedConfig.Key = "other-key"
			case "revision":
				changedEntries[0].AIRevision++
			}
			changedEndpoint, changedBody, err := analysisRequest(changedConfig, changedEntries)
			if err != nil {
				t.Fatal(err)
			}
			if field == "prompt" {
				changedBody = []byte(strings.ReplaceAll(string(changedBody), "你是业务系统", "你是新版业务系统"))
			}
			if analysisCacheKey(changedEndpoint, changedConfig.Key, changedBody, changedEntries) == key {
				t.Fatalf("changing %s did not invalidate the cache", field)
			}
		})
	}
}
