package sensor

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEventMinimizationAndEphemeralSource(t *testing.T) {
	var output bytes.Buffer
	l, err := NewLogger(&output, "honeypot.test")
	if err != nil {
		t.Fatal(err)
	}
	h := l.Wrap("/api/login", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	r := httptest.NewRequest("POST", "http://example.invalid/api/login?access_token=private-fixture-query", strings.NewReader(`{"password":"private-fixture-password"}`))
	r.RemoteAddr = "198.51.100.40:1234"
	r.Header.Set("Authorization", "Bearer private-fixture-token")
	r.Header.Set("Cookie", "private-fixture-cookie")
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	h(httptest.NewRecorder(), r)
	for _, value := range []string{"private-fixture", "198.51.100.40", "203.0.113.99", "password", "Cookie", "access_token"} {
		if strings.Contains(output.String(), value) {
			t.Fatalf("event leaked input category: %s", value)
		}
	}
	var event Event
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.Status != 401 || event.Route != "/api/login" || event.Source != "honeypot.test" || len(event.PeerTag) != 24 {
		t.Fatalf("event schema: %+v", event)
	}
	if l.peerTag("198.51.100.40:9999") != event.PeerTag {
		t.Fatal("port should not change source tag")
	}
	other, _ := NewLogger(&bytes.Buffer{}, "honeypot.test")
	if other.peerTag(r.RemoteAddr) == event.PeerTag {
		t.Fatal("source tags must change on restart")
	}
}

func TestRequestBoundary(t *testing.T) {
	l, _ := NewLogger(&bytes.Buffer{}, "test")
	h := l.Wrap("/api", func(w http.ResponseWriter, r *http.Request) {
		if !Method(w, r, "POST") {
			return
		}
		var in struct {
			Scenario string `json:"scenario"`
		}
		if Decode(w, r, &in) {
			JSON(w, 200, in)
		}
	})
	for _, tc := range []struct {
		name, body, origin, method string
		want                       int
	}{
		{"valid", `{"scenario":"demo"}`, "", "POST", 200},
		{"legacy upload", `{"scenario":"demo","hostPack":"fixture"}`, "", "POST", 400},
		{"two objects", `{"scenario":"demo"}{}`, "", "POST", 400},
		{"large", `{"scenario":"` + strings.Repeat("a", MaxBody) + `"}`, "", "POST", 413},
		{"cross site", `{}`, "https://untrusted.invalid", "POST", 403},
		{"opaque origin", `{}`, "null", "POST", 403},
		{"method", `{}`, "", "PUT", 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://example.invalid/api", strings.NewReader(tc.body))
			r.Header.Set("Origin", tc.origin)
			w := httptest.NewRecorder()
			h(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d want %d", w.Code, tc.want)
			}
		})
	}
}

func TestSessionExpiryRevocationAndBound(t *testing.T) {
	s := NewSessions()
	token, err := s.New()
	if err != nil || !s.Valid(token) {
		t.Fatal("new session missing")
	}
	s.Delete(token)
	if s.Valid(token) {
		t.Fatal("revoked session accepted")
	}
	token, _ = s.New()
	s.tokens[token] = time.Now().Add(-time.Second)
	if s.Valid(token) {
		t.Fatal("expired session accepted")
	}
	for i := 0; i < 256; i++ {
		if _, err = s.New(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.New(); err == nil {
		t.Fatal("unbounded session allocation")
	}
}
