// Package sensor records minimal server-side events for isolated decoy services.
package sensor

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const MaxBody = 16 << 10

type Event struct {
	Time       string `json:"time"`
	Source     string `json:"source"`
	Kind       string `json:"kind"`
	Route      string `json:"route"`
	Method     string `json:"method"`
	Status     int    `json:"status"`
	DurationMS int64  `json:"duration_ms"`
	PeerTag    string `json:"peer_tag"`
}

type Logger struct {
	mu     sync.Mutex
	out    io.Writer
	salt   [32]byte
	source string
}

func NewLogger(out io.Writer, source string) (*Logger, error) {
	l := &Logger{out: out, source: source}
	_, err := rand.Read(l.salt[:])
	return l, err
}

func (l *Logger) peerTag(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = "unknown"
	}
	mac := hmac.New(sha256.New, l.salt[:])
	_, _ = mac.Write([]byte(host))
	return hex.EncodeToString(mac.Sum(nil)[:12])
}

type response struct {
	http.ResponseWriter
	status int
}

func (w *response) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *response) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

// Wrap takes a fixed route label, never a caller-controlled path or query.
func (l *Logger) Wrap(route string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		// Preserve a same-origin POST's Origin on browser form navigation;
		// no-referrer can turn it into the opaque "null" origin.
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
		rw := &response{ResponseWriter: w}
		if r.Method == http.MethodPost && !SameOrigin(r) {
			http.Error(rw, "origin rejected", http.StatusForbidden)
		} else {
			next(rw, r)
		}
		if rw.status == 0 {
			rw.status = http.StatusOK
		}
		method := r.Method
		switch method {
		case "GET", "POST", "HEAD", "OPTIONS":
		default:
			method = "OTHER"
		}
		event := Event{Time: time.Now().UTC().Format(time.RFC3339Nano), Source: l.source,
			Kind: "http_request", Route: route, Method: method, Status: rw.status,
			DurationMS: time.Since(start).Milliseconds(), PeerTag: l.peerTag(r.RemoteAddr)}
		l.mu.Lock()
		err := json.NewEncoder(l.out).Encode(event)
		l.mu.Unlock()
		if err != nil {
			log.Print("honeypot: event write failed")
		}
	}
}

func SameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host == r.Host
}

func Method(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, m := range allowed {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func JSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// Decode rejects unknown fields (including legacy screenshot/file payloads),
// trailing documents and oversized bodies. Error text never echoes the input.
func Decode(w http.ResponseWriter, r *http.Request, value any) bool {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	err := d.Decode(value)
	if err == nil {
		var trailing any
		if tailErr := d.Decode(&trailing); tailErr != io.EOF {
			if tailErr != nil {
				err = tailErr
			} else {
				err = errors.New("trailing JSON")
			}
		}
	}
	if err == nil {
		return true
	}
	status := http.StatusBadRequest
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		status = http.StatusRequestEntityTooLarge
	}
	JSON(w, status, map[string]any{"ok": false, "error": "invalid demo request"})
	return false
}

type Sessions struct {
	mu     sync.Mutex
	tokens map[string]time.Time
}

func NewSessions() *Sessions { return &Sessions{tokens: make(map[string]time.Time)} }
func (s *Sessions) New() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for token, expiry := range s.tokens {
		if !expiry.After(now) {
			delete(s.tokens, token)
		}
	}
	if len(s.tokens) >= 256 {
		return "", errors.New("demo sessions full")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	s.tokens[token] = now.Add(30 * time.Minute)
	return token, nil
}
func (s *Sessions) Valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.tokens[token]
	if !ok {
		return false
	}
	if !expiry.After(time.Now()) {
		delete(s.tokens, token)
		return false
	}
	return true
}
func (s *Sessions) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
}

// Run is shared by both portals. Only the explicit listen flag can expose them.
func Run(component, defaultListen string, build func(*Logger) http.Handler) {
	listen := flag.String("listen", defaultListen, "listen address; loopback by default")
	events := flag.String("events", "", "optional JSONL path; default: stdout")
	flag.Parse()
	var out io.Writer = os.Stdout
	if *events != "" {
		if err := os.MkdirAll(filepath.Dir(*events), 0o700); err != nil {
			log.Fatal("cannot create event directory")
		}
		f, err := os.OpenFile(*events, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatal("cannot open event log")
		}
		defer f.Close()
		out = f
	}
	l, err := NewLogger(out, component)
	if err != nil {
		log.Fatal("cannot initialize event salt")
	}
	server := &http.Server{Addr: *listen, Handler: build(l), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	log.Printf("%s demo listening on %s", component, *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal("honeypot server stopped; check listen address and local permissions")
	}
}
