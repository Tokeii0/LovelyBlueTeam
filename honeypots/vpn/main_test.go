package main

import (
	"bytes"
	"lovely-honeypots/internal/sensor"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVPNRoutesAndRejectedCollection(t *testing.T) {
	var events bytes.Buffer
	l, _ := sensor.NewLogger(&events, "honeypot.vpn")
	h := handler(l)
	for _, tc := range []struct {
		method, path, body, contains string
		status                       int
	}{
		{"GET", "/", "", "Lovely VPN", 200},
		{"GET", "/client", "", "demo-bridge.js", 200},
		{"GET", "/resources", "", "合成资源", 200},
		{"GET", "/auth.js", "", "/api/login", 200},
		{"POST", "/api/login", `{"user":"demo","password":"demo"}`, `"synthetic":true`, 200},
		{"POST", "/api/login", `{"user":"fixture-user","password":"fixture-password"}`, `"ok":false`, 401},
		{"POST", "/api/connect", `{"scenario":"demo"}`, `"tunnel":false`, 200},
		{"POST", "/api/connect", `{"scenario":"demo","screenshot":{"data":"fixture-screen"}}`, "invalid demo", 400},
		{"POST", "/api/host", `{"hostPack":"fixture-files"}`, "404", 404},
		{"GET", "/downloads/client.exe", "", "404", 404},
		{"POST", "/styles.css", "", "method not allowed", 405},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			h.ServeHTTP(w, r)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.contains) {
				t.Fatalf("status=%d body-prefix=%.100s", w.Code, w.Body.String())
			}
		})
	}
	if strings.Contains(events.String(), "fixture-") {
		t.Fatal("credentials or payload persisted")
	}
}
