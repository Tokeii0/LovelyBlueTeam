package main

import (
	"embed"
	"lovely-honeypots/internal/sensor"
	"net/http"
)

//go:embed web/*
var web embed.FS

func handler(events *sensor.Logger) http.Handler {
	mux := http.NewServeMux()
	pages := map[string]string{"/": "index.html", "/client": "client.html", "/resources": "resources.html",
		"/styles.css": "styles.css", "/auth.css": "auth.css", "/auth.js": "auth.js",
		"/portal.js": "portal.js", "/demo-bridge.js": "demo-bridge.js"}
	for path, file := range pages {
		mux.HandleFunc(path, events.Wrap(path, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				http.NotFound(w, r)
				return
			}
			if !sensor.Method(w, r, "GET", "HEAD") {
				return
			}
			data, err := web.ReadFile("web/" + file)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			contentType := "text/html; charset=utf-8"
			if len(file) > 4 && file[len(file)-4:] == ".css" {
				contentType = "text/css; charset=utf-8"
			}
			if len(file) > 3 && file[len(file)-3:] == ".js" {
				contentType = "text/javascript; charset=utf-8"
			}
			w.Header().Set("Content-Type", contentType)
			if r.Method != "HEAD" {
				_, _ = w.Write(data)
			}
		}))
	}
	mux.HandleFunc("/healthz", events.Wrap("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if sensor.Method(w, r, "GET", "HEAD") {
			sensor.JSON(w, 200, map[string]any{"ok": true, "synthetic": true})
		}
	}))
	mux.HandleFunc("/api/login", events.Wrap("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if !sensor.Method(w, r, "POST") {
			return
		}
		var in struct {
			User     string `json:"user"`
			Password string `json:"password"`
		}
		if !sensor.Decode(w, r, &in) {
			return
		}
		if (in.User != "demo" && in.User != "00000000") || in.Password != "demo" {
			sensor.JSON(w, 401, map[string]any{"ok": false, "error": "请使用公开演示凭据"})
			return
		}
		sensor.JSON(w, 200, map[string]any{"ok": true, "name": "示例用户", "synthetic": true})
	}))
	mux.HandleFunc("/api/connect", events.Wrap("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		if !sensor.Method(w, r, "POST") {
			return
		}
		var in struct {
			Scenario string `json:"scenario"`
		}
		if !sensor.Decode(w, r, &in) {
			return
		}
		if in.Scenario != "demo" {
			sensor.JSON(w, 400, map[string]any{"ok": false})
			return
		}
		sensor.JSON(w, 200, map[string]any{"ok": true, "synthetic": true, "user": "示例用户", "ip": "192.0.2.10", "tunnel": false})
	}))
	return mux
}

func main() { sensor.Run("honeypot.vpn", "127.0.0.1:8801", handler) }
