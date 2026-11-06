package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefenseRetryRestartAndStructuredReceipts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "defense.db")
	store, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if store != nil {
			store.db.Close()
		}
	}()
	entry := makeEntry(`{"time":"2026-11-04T19:00:00+08:00","ip":"8.8.8.8","method":"POST","uri":"/api?token=uri-private","body":"{\"body\":{\"patient_id\":\"patient-private\",\"query\":\"union select 1\"}}","status":"200"}`, nil)
	if err = store.commit("source", ReadCursor{}, []Entry{entry, entry}); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	failFirst := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") && (r.Header.Get("X-Agent-ID") != "11111111-1111-1111-1111-111111111111" || r.Header.Get("Authorization") != "Bearer fixture-agent-token-1234567890") {
			t.Error("missing receiver credentials")
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/ingest":
			var body struct {
				Events []struct {
					ID  string `json:"eventId"`
					Raw string `json:"raw"`
				} `json:"events"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("invalid outgoing JSON")
			}
			for _, e := range body.Events {
				if old, ok := seen[e.ID]; ok && old != e.Raw {
					t.Error("retried ID changed payload")
				}
				seen[e.ID] = e.Raw
				if strings.Contains(e.Raw, "-private") || !strings.Contains(e.Raw, "union select 1") {
					t.Error("redaction lost evidence or exposed patient identifiers")
				}
			}
			if failFirst {
				failFirst = false
				w.WriteHeader(503)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(body.Events)})
		case "/v1/verdicts":
			var body struct {
				IDs []string `json:"eventIds"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			rows := []map[string]any{}
			for _, id := range body.IDs {
				rows = append(rows, map[string]any{"event_id": id, "ai_state": "analyzed", "decision": map[string]any{"id": 12, "ip": "8.8.8.8", "attack": 1, "confidence": .99, "category": "sql_injection", "reason": "测试载荷", "state": "listed", "cited": true}, "block": map[string]any{"state": "listed"}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"events": rows})
		case "/api/ai":
			_ = json.NewEncoder(w).Encode(map[string]any{"settings": map[string]any{"enabled": true, "autoBlock": true, "threshold": .95, "model": "fixture"}})
		case "/api/af":
			_, _ = w.Write([]byte(`{"settings":{"enabled":true},"status":{}}`))
		default:
			t.Error("unexpected path " + r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	config := Config{LogPath: "/opt/1panel/www/sites/example-app/log/post.log", Defense: DefenseConfig{Enabled: true, HubURL: server.URL, LivelogURL: server.URL, AgentID: "11111111-1111-1111-1111-111111111111", Token: "fixture-agent-token-1234567890"}}
	if err = config.Defense.validate(); err != nil {
		t.Fatal(err)
	}
	d := newDefense(config, store)
	if _, err = d.once(context.Background()); err == nil {
		t.Fatal("unacknowledged upload must not advance the cursor")
	}
	if len(seen) != 2 {
		t.Fatal("real repeated requests must have separate IDs")
	}
	store.db.Close()
	store = nil
	store, err = openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	d = newDefense(config, store)
	if n, err := d.once(context.Background()); err != nil || n != 2 {
		t.Fatalf("durable retry failed: %d %v", n, err)
	}
	if len(seen) != 2 || d.status().Pending != 0 || d.status().Submitted != 2 || !d.status().AutoBlock || !d.status().AFEnabled {
		t.Fatal("duplicate evidence or missing defense status")
	}
	for _, id := range []uint64{1, 2} {
		e, err := store.entry(id)
		if err != nil || e.Defense == nil || e.Defense.Decision == nil || e.Defense.Decision.State != "listed" {
			t.Fatal("confirmed receipt not persisted")
		}
	}
	if n, err := d.once(context.Background()); err != nil || n != 0 {
		t.Fatal("completed records replayed")
	}
}

func TestDefensePayloadBoundsAndOpaqueBody(t *testing.T) {
	e := Entry{Method: "POST", URI: "/api", Decoded: Decoded{State: "encrypted", Message: "missing key"}, Body: "opaque-private-value", Received: time.Now()}
	raw, err := defenseRaw(e)
	if err != nil || strings.Contains(raw, e.Body) {
		t.Fatal("opaque ciphertext must not be called plaintext")
	}
	e.Decoded = Decoded{State: "plain", Text: strings.Repeat("中文\"<", 20000)}
	raw, err = defenseRaw(e)
	if err != nil || len(raw) > 16384 || !json.Valid([]byte(raw)) {
		t.Fatal("large body broke the bounded JSON contract")
	}
	var obj map[string]any
	_ = json.Unmarshal([]byte(raw), &obj)
	if obj["body_truncated"] != true {
		t.Fatal("missing truncation marker")
	}
	bad := DefenseConfig{Enabled: true, HubURL: "http://remote.invalid", LivelogURL: "http://127.0.0.1:8787"}
	if bad.validate() == nil {
		t.Fatal("credentials may only be bridged to local services")
	}
}
