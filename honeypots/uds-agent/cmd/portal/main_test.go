package main

import (
	"bytes"
	"lovely-honeypots/internal/sensor"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPortalSessionDocumentsAndNoDownload(t *testing.T) {
	var events bytes.Buffer
	l, _ := sensor.NewLogger(&events, "honeypot.uds")
	h := handler(l, true)
	request := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if method == "POST" {
			r.Header.Set("Origin", "http://"+r.Host)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/portal", "", nil); w.Code != 302 {
		t.Fatal("unauthenticated portal")
	}
	if w := request("GET", "/login", "", nil); w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("browser form navigation must preserve its same-origin Origin")
	}
	if w := request("POST", "/login?username=demo&password=demo", "", nil); w.Code != 401 {
		t.Fatal("query credentials accepted")
	}
	if w := request("POST", "/login", "username=fixture-account&password=fixture-secret", nil); w.Code != 401 {
		t.Fatal("non-demo credentials accepted")
	}
	w := request("POST", "/login", "username=demo&password=demo", nil)
	if w.Code != 303 || len(w.Result().Cookies()) != 1 {
		t.Fatal("demo login failed")
	}
	c := w.Result().Cookies()[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.MaxAge != 1800 {
		t.Fatal("cookie attributes")
	}
	for name := range docIndex {
		for _, path := range []string{"/portal?doc=" + name, "/docs/" + name} {
			w = request("GET", path, "", c)
			if w.Code != 200 || strings.Contains(w.Body.String(), "%!") {
				t.Fatalf("document render failed: %s", name)
			}
		}
	}
	if w = request("GET", "/download/agent", "", c); w.Code != 404 {
		t.Fatal("client download exposed")
	}
	if w = request("GET", "/docs/../../source.go", "", c); w.Code == 200 {
		t.Fatal("file route escaped document set")
	}
	request("POST", "/logout", "", c)
	if w = request("GET", "/portal", "", c); w.Code != 302 {
		t.Fatal("logout did not revoke session")
	}
	for _, secret := range []string{"fixture-", c.Value, "username=", "password="} {
		if strings.Contains(events.String(), secret) {
			t.Fatal("request secrets in event log")
		}
	}
}

func TestPortalTokenRejectsMalformedAndOversizedRequests(t *testing.T) {
	l, _ := sensor.NewLogger(&bytes.Buffer{}, "test")
	h := handler(l, false)
	for _, tc := range []struct {
		body string
		code int
	}{
		{`{"username":"demo","password":"demo"}`, 200},
		{`{"username":"demo","password":"demo","hostname":"fixture-host"}`, 400},
		{`{"username":"demo","password":"demo"}{}`, 400},
		{`{"username":"` + strings.Repeat("a", sensor.MaxBody) + `","password":"demo"}`, 413},
	} {
		r := httptest.NewRequest("POST", "/api/auth/token", strings.NewReader(tc.body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("got %d want %d", w.Code, tc.code)
		}
	}
}
