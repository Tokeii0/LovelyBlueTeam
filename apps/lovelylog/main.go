package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var assets embed.FS

type App struct {
	config    Config
	store     *Store
	collector *Collector
	defense   *DefenseWorker
	aiMu      sync.Mutex
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func (a *App) allowed(r *http.Request) bool {
	_, port, _ := net.SplitHostPort(a.config.Listen)
	host, requestPort, err := net.SplitHostPort(r.Host)
	if err != nil || requestPort != port || (host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback())) {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "http" || u.Host != r.Host {
			return false
		}
	}
	return r.Header.Get("Sec-Fetch-Site") != "cross-site"
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if !a.allowed(r) {
		fail(w, 403, errors.New("仅允许本机同源访问"))
		return
	}
	if r.Method == http.MethodGet {
		switch r.URL.Path {
		case "/api/status":
			defense := DefenseStatus{}
			if a.defense != nil {
				defense = a.defense.status()
			}
			mode := a.config.AnalysisMode
			if mode == "" {
				mode = "ai"
			}
			writeJSON(w, 200, map[string]any{"app": "LovelyLog", "version": "1.2.1", "counts": a.store.counts(), "collector": a.collector.status(), "profiles": profileInfo(a.config.Profiles), "analysis_mode": mode, "analysis_scope": "lovelylog", "analysis_available": mode == "local" || a.config.AI.Key != "", "local_rules_version": localRulesVersion, "ai_configured": mode != "local" && a.config.AI.Key != "", "ai_model": a.config.AI.Model, "poll_seconds": a.config.PollSeconds, "defense": defense, "key_files": a.config.keyInfo})
		case "/api/entries":
			q := r.URL.Query()
			before, err := strconv.ParseUint(q.Get("before"), 10, 64)
			if q.Get("before") != "" && err != nil {
				fail(w, 400, errors.New("翻页参数无效"))
				return
			}
			if len(q.Get("q")) > 500 {
				fail(w, 400, errors.New("搜索词过长"))
				return
			}
			page, err := a.store.list(Query{Before: before, Text: q.Get("q"), State: q.Get("state"), Limit: 100, Suspicious: q.Get("suspicious") == "true"})
			if err != nil {
				fail(w, 500, errors.New("读取本地日志失败"))
				return
			}
			writeJSON(w, 200, page)
		case "/api/entry":
			id, err := strconv.ParseUint(r.URL.Query().Get("id"), 10, 64)
			if err != nil || id == 0 {
				fail(w, 400, errors.New("记录编号无效"))
				return
			}
			e, err := a.store.entry(id)
			if err != nil {
				fail(w, 404, err)
				return
			}
			preview, err := aiPayload([]Entry{e})
			if err != nil {
				fail(w, 500, errors.New("无法生成送审预览"))
				return
			}
			automaticPreview := ""
			if a.config.Defense.Enabled {
				automaticPreview, _ = defenseRaw(e)
			}
			writeJSON(w, 200, map[string]any{"entry": e, "ai_preview": string(preview), "automatic_preview": automaticPreview})
		case "/", "/app.js", "/styles.css":
			path := r.URL.Path
			if path == "/" {
				path = "/index.html"
			}
			data, err := fs.ReadFile(assets, "web"+path)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			switch {
			case strings.HasSuffix(path, ".js"):
				w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			case strings.HasSuffix(path, ".css"):
				w.Header().Set("Content-Type", "text/css; charset=utf-8")
			default:
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
			}
			_, _ = w.Write(data)
		default:
			http.NotFound(w, r)
		}
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(w, 415, errors.New("需要 JSON 请求"))
		return
	}
	if r.URL.Path != "/api/analyze" && r.URL.Path != "/api/redecode" {
		http.NotFound(w, r)
		return
	}
	var body struct {
		IDs []uint64 `json:"ids"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil || len(body.IDs) < 1 || len(body.IDs) > 10 {
		fail(w, 400, errors.New("每次选择 1–10 条日志"))
		return
	}
	if !a.aiMu.TryLock() {
		fail(w, 409, errors.New("正在分析或重新解析上一批日志，请稍后重试"))
		return
	}
	defer a.aiMu.Unlock()
	entries := []Entry{}
	seen := map[uint64]bool{}
	for _, id := range body.IDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		e, err := a.store.entry(id)
		if err != nil {
			fail(w, 404, err)
			return
		}
		entries = append(entries, e)
	}
	if r.URL.Path == "/api/redecode" {
		for _, entry := range entries {
			err := a.store.updateEntry(entry.ID, func(e *Entry) {
				e.Decoded = decodeBody(e.Body, e.URI, a.config.Profiles)
				e.Findings = localFindings(*e)
				e.AIReport = ""
				e.AIModel = ""
				e.AIAt = time.Time{}
				e.AIRevision++
				e.LocalReport = ""
				e.LocalAt = time.Time{}
			})
			if err != nil {
				fail(w, 500, err)
				return
			}
		}
		writeJSON(w, 200, map[string]int{"updated": len(entries)})
		return
	}
	if a.config.AnalysisMode == "local" {
		report := localReview(entries)
		for _, entry := range entries {
			if err := a.store.updateEntry(entry.ID, func(e *Entry) { e.LocalReport = report; e.LocalAt = time.Now() }); err != nil {
				fail(w, 500, errors.New("本地复核完成，但保存报告失败"))
				return
			}
		}
		writeJSON(w, 200, map[string]any{"report": report, "provider": "local", "model": localRulesVersion, "analysis_mode": "local", "cached": false})
		return
	}
	endpoint, requestBody, err := analysisRequest(a.config.AI, entries)
	if err != nil {
		fail(w, 502, err)
		return
	}
	cacheKey := analysisCacheKey(endpoint, a.config.AI.Key, requestBody, entries)
	report, cached, err := a.store.cachedAnalysis(cacheKey)
	if err != nil {
		fail(w, 500, errors.New("读取本地分析缓存失败，未调用模型"))
		return
	}
	if !cached {
		text, err := requestPreparedAnalysis(r.Context(), a.config.AI.Key, endpoint, requestBody)
		if err != nil {
			fail(w, 502, err)
			return
		}
		report = AnalysisReport{Report: text, Model: a.config.AI.Model, At: time.Now()}
	}
	if err := a.store.saveAnalysis(cacheKey, report, entries); err != nil {
		fail(w, 500, errors.New("分析完成，但写入本地报告失败"))
		return
	}
	writeJSON(w, 200, map[string]any{"report": report.Report, "model": report.Model, "cached": cached})
}

func reprocess(store *Store, profiles []CryptoProfile) (int, error) {
	count := 0
	before := uint64(0)
	for {
		page, err := store.list(Query{Before: before, Limit: 100})
		if err != nil {
			return count, err
		}
		for _, row := range page.Entries {
			err = store.updateEntry(row.ID, func(e *Entry) {
				e.Decoded = decodeBody(e.Body, e.URI, profiles)
				e.Findings = localFindings(*e)
				e.AIReport = ""
				e.AIModel = ""
				e.AIAt = time.Time{}
				e.AIRevision++
				e.LocalReport = ""
				e.LocalAt = time.Time{}
			})
			if err != nil {
				return count, err
			}
			count++
		}
		if !page.HasMore {
			break
		}
		before = page.Before
	}
	return count, nil
}

func main() {
	configPath := flag.String("config", "config.local.json", "本地配置文件")
	once := flag.Bool("once", false, "拉取一次后退出，不启动网页、不调用 AI")
	redo := flag.Bool("reprocess", false, "用当前解密配置重新解析本地已保存记录")
	flag.Parse()
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Printf("启动失败：%v", err)
		os.Exit(1)
	}
	store, err := openStore(config.DataFile)
	if err != nil {
		log.Printf("打开本地数据库失败：%v", err)
		os.Exit(1)
	}
	defer store.db.Close()
	if *redo {
		n, err := reprocess(store, config.Profiles)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("重新解析 %d 条本地记录（没有调用 AI）", n)
	}
	collector := newCollector(config, store)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if *once {
		n, err := collector.once(ctx)
		if err != nil {
			log.Printf("拉取失败：%v", err)
			os.Exit(1)
		}
		data, _ := json.Marshal(map[string]any{"new_records": n, "counts": store.counts(), "collector": collector.status()})
		fmt.Println(string(data))
		return
	}
	defense := newDefense(config, store)
	app := &App{config: config, store: store, collector: collector, defense: defense}
	server := &http.Server{Addr: config.Listen, Handler: app, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second}
	var workers sync.WaitGroup
	if config.Defense.Enabled {
		workers.Add(1)
		go func() { defer workers.Done(); defense.run(ctx) }()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				_, err := collector.once(ctx)
				if err != nil && ctx.Err() == nil {
					log.Printf("采集：%v", err)
				}
				timer.Reset(time.Duration(config.PollSeconds) * time.Second)
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("LovelyLog 已启动：http://%s （Ctrl+C 停止）", config.Listen)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("网页服务失败：%v", err)
	}
	cancel()
	workers.Wait()
}
