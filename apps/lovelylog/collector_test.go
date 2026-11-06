package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type logFixture struct {
	mu      sync.Mutex
	content []byte
	ranges  []string
}

func (f *logFixture) set(text string) { f.mu.Lock(); defer f.mu.Unlock(); f.content = []byte(text) }
func (f *logFixture) add(text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.content = append(f.content, []byte(text)...)
}
func (f *logFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	timestamp := r.Header.Get("1Panel-Timestamp")
	hash := md5.Sum([]byte("1paneltest-key" + timestamp))
	if timestamp == "" || r.Header.Get("1Panel-Token") != hex.EncodeToString(hash[:]) {
		http.Error(w, "secret-error", 403)
		return
	}
	if r.URL.Query().Get("path") != "/opt/1panel/www/sites/example-app/log/post.log" {
		http.Error(w, "wrong path", 400)
		return
	}
	value := r.Header.Get("Range")
	f.ranges = append(f.ranges, value)
	size := len(f.content)
	var start, end int
	if strings.HasPrefix(value, "bytes=-") {
		n, _ := strconv.Atoi(strings.TrimPrefix(value, "bytes=-"))
		start, end = max(0, size-n), size-1
	} else {
		_, _ = fmt.Sscanf(value, "bytes=%d-%d", &start, &end)
		end = min(end, size-1)
	}
	if size == 0 || start > end {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
		w.WriteHeader(416)
		return
	}
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
	w.WriteHeader(206)
	_, _ = w.Write(f.content[start : end+1])
}

func fixtureConfig(url string) Config {
	return Config{PanelURL: url, PanelKey: "test-key", PanelPrefix: "/api/v2", LogPath: "/opt/1panel/www/sites/example-app/log/post.log", InitialLines: 200, Listen: "127.0.0.1:8790", PollSeconds: 3}
}
func logLine(body string) string {
	return fmt.Sprintf(`{"time":"2026-11-04T19:00:00+08:00","ip":"8.8.8.8","method":"POST","uri":"/test","body":%q,"status":"200"}`, body)
}

func TestCollectorResumesPartialUTF8AndPreservesRealDuplicates(t *testing.T) {
	fixture := &logFixture{}
	upstream := httptest.NewServer(http.HandlerFunc(fixture.serve))
	defer upstream.Close()
	path := filepath.Join(t.TempDir(), "test.db")
	store, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	config := fixtureConfig(upstream.URL)
	collector := newCollector(config, store)
	line := logLine("中文正文")
	cut := strings.Index(line, "中") + 1
	fixture.set(line[:cut])
	if n, err := collector.once(context.Background()); err != nil || n != 0 {
		t.Fatalf("partial row committed: %d %v", n, err)
	}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	collector = newCollector(config, store)
	fixture.add(line[cut:] + "\n" + line + "\n")
	if n, err := collector.once(context.Background()); err != nil || n != 2 {
		t.Fatalf("resume rows %d %v", n, err)
	}
	if n, err := collector.once(context.Background()); err != nil || n != 0 {
		t.Fatal("replayed already-read data")
	}
	page, err := store.list(Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 2 || store.counts()["plain"] != 2 {
		t.Fatal("duplicate lines were dropped")
	}
	entry, _ := store.entry(1)
	if entry.Raw != line || entry.Body != "中文正文" {
		t.Fatal("split UTF-8 content changed")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	for _, value := range fixture.ranges[1:] {
		if strings.HasPrefix(value, "bytes=-") {
			t.Fatal("incremental collection re-read file tail")
		}
	}
}

func TestCollectorTailRotationAndEmptyFile(t *testing.T) {
	fixture := &logFixture{}
	upstream := httptest.NewServer(http.HandlerFunc(fixture.serve))
	defer upstream.Close()
	store, err := openStore(filepath.Join(t.TempDir(), "logs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	config := fixtureConfig(upstream.URL)
	config.InitialLines = 2
	collector := newCollector(config, store)
	fixture.set(logLine("one") + "\n" + logLine("two") + "\n" + logLine("three") + "\n")
	if n, err := collector.once(context.Background()); err != nil || n != 2 {
		t.Fatalf("tail failed %d %v", n, err)
	}
	first, _ := store.entry(1)
	if first.Body != "two" {
		t.Fatal("initial tail contains wrong rows")
	}
	fixture.set(logLine("replacement") + "\n")
	if n, err := collector.once(context.Background()); err != nil || n != 1 {
		t.Fatalf("rotation failed %d %v", n, err)
	}
	third, _ := store.entry(3)
	if third.Generation != 1 {
		t.Fatal("rotation generation not saved")
	}
	fixture.set("")
	if n, err := collector.once(context.Background()); err != nil || n != 0 {
		t.Fatal("empty log failed")
	}
	fixture.add(logLine("after-clear") + "\n")
	if n, err := collector.once(context.Background()); err != nil || n != 1 {
		t.Fatalf("after-clear failed %d %v", n, err)
	}
}

func TestPaginationAndQueryKeepStableCursor(t *testing.T) {
	store, err := openStore(filepath.Join(t.TempDir(), "query.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.db.Close()
	entries := []Entry{}
	for i := 0; i < 213; i++ {
		entries = append(entries, makeEntry(logLine(fmt.Sprintf("正文%d", i)), nil))
	}
	if err := store.commit("test", ReadCursor{Offset: 123}, entries); err != nil {
		t.Fatal(err)
	}
	before := uint64(0)
	seen := map[uint64]bool{}
	for {
		page, err := store.list(Query{Before: before, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page.Entries {
			if seen[e.ID] {
				t.Fatal("duplicate pagination row")
			}
			seen[e.ID] = true
		}
		if !page.HasMore {
			break
		}
		before = page.Before
	}
	if len(seen) != 213 {
		t.Fatalf("missing rows %d", len(seen))
	}
	page, _ := store.list(Query{Text: "正文212", Limit: 100})
	if len(page.Entries) != 1 {
		t.Fatal("search missed decrypted body")
	}
	cursor, _ := store.cursor("test")
	if cursor.Offset != 123 {
		t.Fatal("data and cursor not saved together")
	}
}
