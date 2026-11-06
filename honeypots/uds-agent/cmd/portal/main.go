// Portal serves synthetic integration documentation and minimal request events.
package main

import (
	"flag"
	"fmt"
	"html"
	"lovely-honeypots/internal/sensor"
	"net/http"
	"strings"
)

const cookieName = "LOVELY_DEMO_SESSION"

func tokenFrom(r *http.Request) string {
	if c, err := r.Cookie(cookieName); err == nil {
		return c.Value
	}
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func handler(events *sensor.Logger, secureCookies bool) http.Handler {
	mux := http.NewServeMux()
	sessions := sensor.NewSessions()
	loginView := func(w http.ResponseWriter, message string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, loginPage, html.EscapeString(message))
	}
	issue := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		token, err := sessions.New()
		if err != nil {
			http.Error(w, "demo session capacity reached", 503)
			return "", false
		}
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", HttpOnly: true,
			SameSite: http.SameSiteStrictMode, Secure: secureCookies || r.TLS != nil, MaxAge: 1800})
		return token, true
	}
	mux.HandleFunc("/", events.Wrap("<unmatched>", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if sensor.Method(w, r, "GET", "HEAD") {
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	}))
	mux.HandleFunc("/healthz", events.Wrap("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if sensor.Method(w, r, "GET", "HEAD") {
			sensor.JSON(w, 200, map[string]any{"ok": true, "synthetic": true})
		}
	}))
	mux.HandleFunc("/login", events.Wrap("/login", func(w http.ResponseWriter, r *http.Request) {
		if !sensor.Method(w, r, "GET", "HEAD", "POST") {
			return
		}
		if r.Method != "POST" {
			loginView(w, "")
			return
		}
		if r.ParseForm() != nil {
			http.Error(w, "invalid demo form", 400)
			return
		}
		// Query-string credentials are never accepted.
		if r.PostForm.Get("username") != "demo" || r.PostForm.Get("password") != "demo" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(401)
			loginView(w, "请使用公开演示凭据 demo / demo")
			return
		}
		if _, ok := issue(w, r); ok {
			http.Redirect(w, r, "/portal", http.StatusSeeOther)
		}
	}))
	mux.HandleFunc("/api/auth/token", events.Wrap("/api/auth/token", func(w http.ResponseWriter, r *http.Request) {
		if !sensor.Method(w, r, "POST") {
			return
		}
		var in struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !sensor.Decode(w, r, &in) {
			return
		}
		if in.Username != "demo" || in.Password != "demo" {
			sensor.JSON(w, 401, map[string]any{"ok": false, "error": "demo credentials required"})
			return
		}
		if token, ok := issue(w, r); ok {
			sensor.JSON(w, 200, map[string]any{"ok": true, "synthetic": true, "data": map[string]any{"accessToken": token, "tokenType": "Bearer", "expiresIn": 1800}})
		}
	}))
	mux.HandleFunc("/logout", events.Wrap("/logout", func(w http.ResponseWriter, r *http.Request) {
		if !sensor.Method(w, r, "POST") {
			return
		}
		sessions.Delete(tokenFrom(r))
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: secureCookies || r.TLS != nil})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}))
	mux.HandleFunc("/portal", events.Wrap("/portal", func(w http.ResponseWriter, r *http.Request) {
		if !sensor.Method(w, r, "GET", "HEAD") {
			return
		}
		if !sessions.Valid(tokenFrom(r)) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		name := r.URL.Query().Get("doc")
		d, ok := docIndex[name]
		if !ok {
			name = "overview"
			d = docIndex[name]
		}
		var nav strings.Builder
		for _, g := range navTree {
			fmt.Fprintf(&nav, `<div class="g">%s</div>`, html.EscapeString(g.Group))
			for _, e := range g.Docs {
				cls := ""
				if e.Name == name {
					cls = ` class="on"`
				}
				fmt.Fprintf(&nav, `<a href="/portal?doc=%s"%s>%s</a>`, e.Name, cls, html.EscapeString(e.Title))
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, portalPage, "demo", "本次登录后 30 分钟", nav.String(), d.Title, d.Ver, d.Date, d.Body)
	}))
	mux.HandleFunc("/docs/", events.Wrap("/docs/*", func(w http.ResponseWriter, r *http.Request) {
		if !sensor.Method(w, r, "GET", "HEAD") {
			return
		}
		if !sessions.Valid(tokenFrom(r)) {
			http.Error(w, "demo session required", 401)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/docs/")
		d, ok := docIndex[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>%s</title><h1>合成演示文档</h1>%s", html.EscapeString(d.Title), d.Body)
	}))
	return mux
}

func main() {
	secure := flag.Bool("secure-cookies", false, "set when deployed behind your HTTPS reverse proxy")
	sensor.Run("honeypot.uds", "127.0.0.1:8802", func(l *sensor.Logger) http.Handler { return handler(l, *secure) })
}
