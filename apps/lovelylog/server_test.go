package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalWebRejectsCrossOriginAndDoesNotExposeCredentials(t *testing.T) {
	store, err := openStore(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	config := fixtureConfig("http://127.0.0.1:1")
	config.PanelKey = "panel-private-secret"
	config.AI = AIConfig{"https://model.example", "model-private-secret", "fixture-model"}
	app := &App{config: config, store: store, collector: newCollector(config, store)}
	for _, path := range []string{"/", "/app.js", "/styles.css", "/api/status", "/api/entries"} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:8790"+path, nil)
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("asset %s returned %d", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "private-secret") {
			t.Fatal("credential exposed")
		}
	}
	for _, headers := range []map[string]string{{"Origin": "https://evil.example"}, {"Host": "evil.example:8790"}, {"Sec-Fetch-Site": "cross-site"}} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:8790/api/status", nil)
		for k, v := range headers {
			if k == "Host" {
				r.Host = v
			} else {
				r.Header.Set(k, v)
			}
		}
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("cross-origin request was allowed")
		}
	}
	for _, path := range []string{"/.env", "/config.local.json", "/../config.local.json", "/main.go", "/web/index.html"} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:8790"+path, nil)
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal("private file accessible")
		}
	}
	r := httptest.NewRequest("POST", "http://127.0.0.1:8790/api/analyze", strings.NewReader(`{"ids":[1]}`))
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatal("JSON content type not enforced")
	}
}

func TestConfigReusesLivelogWithoutCopyingSecretsToPublicAPI(t *testing.T) {
	dir := t.TempDir()
	env := []byte("PANEL_URL=http://10.20.30.13:18479\nPANEL_API_KEY=panel-secret\nPANEL_API_PREFIX=/api/v2\nDEEPSEEK_BASE_URL=https://api.deepseek.com\nDEEPSEEK_API_KEY=model-secret\nDEEPSEEK_MODEL=test-model\n")
	if err := os.WriteFile(filepath.Join(dir, "livelog.env"), env, 0600); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(Config{EnvFile: "livelog.env"})
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.AnalysisMode != "local" {
		t.Fatal("missing mode must default to local")
	}
	if c.PanelKey != "panel-secret" || c.AI.Key != "model-secret" || c.AI.Model != "test-model" {
		t.Fatal("did not load existing configuration")
	}
	if c.LogPath != "/opt/1panel/www/sites/example-app/log/post.log" || !filepath.IsAbs(c.DataFile) {
		t.Fatal("default path incorrect")
	}
	for _, listen := range []string{"0.0.0.0:8790", "192.168.1.1:8790", "127.0.0.1"} {
		data, _ := json.Marshal(Config{EnvFile: "livelog.env", Listen: listen})
		_ = os.WriteFile(path, data, 0600)
		if _, err := loadConfig(path); err == nil {
			t.Fatalf("unsafe listener accepted: %s", listen)
		}
	}
}
