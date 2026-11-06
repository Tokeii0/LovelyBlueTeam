package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

type DefenseConfig struct {
	Enabled    bool   `json:"enabled"`
	HubURL     string `json:"hub_url,omitempty"`
	LivelogURL string `json:"livelog_url,omitempty"`
	AgentID    string `json:"agent_id,omitempty"`
	Token      string `json:"agent_token,omitempty"`
}

func (c *DefenseConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if c.HubURL == "" {
		c.HubURL = "http://127.0.0.1:8788"
	}
	if c.LivelogURL == "" {
		c.LivelogURL = "http://127.0.0.1:8787"
	}
	for _, endpoint := range []string{c.HubURL, c.LivelogURL} {
		if err := validEndpoint(endpoint); err != nil {
			return errors.New("防护服务地址无效")
		}
		u, _ := url.Parse(endpoint)
		ip := net.ParseIP(u.Hostname())
		if (ip == nil || !ip.IsLoopback()) && u.Hostname() != "localhost" {
			return errors.New("防护桥接仅支持本机 Livelog 地址")
		}
	}
	if !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(c.AgentID) || len(c.Token) < 20 || len(c.Token) > 200 {
		return errors.New("自动防护需要有效的 Livelog 代理凭据")
	}
	c.HubURL = strings.TrimRight(c.HubURL, "/")
	c.LivelogURL = strings.TrimRight(c.LivelogURL, "/")
	return nil
}

type DefenseDecision struct {
	ID         uint64  `json:"id"`
	IP         string  `json:"ip"`
	Attack     int     `json:"attack"`
	Confidence float64 `json:"confidence"`
	Category   string  `json:"category"`
	Reason     string  `json:"reason"`
	State      string  `json:"state"`
	Detail     string  `json:"detail"`
	Provider   string  `json:"provider"`
	Model      string  `json:"model"`
	Historical int     `json:"historical"`
	Cited      bool    `json:"cited"`
}
type DefenseReceipt struct {
	DecodedSHA256 string           `json:"decoded_sha256,omitempty"`
	EventID       string           `json:"event_id"`
	AIState       string           `json:"ai_state"`
	SentAt        time.Time        `json:"sent_at"`
	CheckedAt     time.Time        `json:"checked_at"`
	Decision      *DefenseDecision `json:"decision,omitempty"`
	Block         *struct {
		State   string  `json:"state"`
		Updated float64 `json:"updated"`
	} `json:"block,omitempty"`
}
type DefenseStatus struct {
	Enabled              bool      `json:"enabled"`
	Connected            bool      `json:"connected"`
	Error                string    `json:"error,omitempty"`
	LastSent             time.Time `json:"last_sent"`
	CheckedAt            time.Time `json:"checked_at"`
	Submitted            uint64    `json:"submitted"`
	Pending              uint64    `json:"pending"`
	LivelogURL           string    `json:"livelog_url,omitempty"`
	AIEnabled            bool      `json:"ai_enabled"`
	AutoBlock            bool      `json:"auto_block"`
	Threshold            float64   `json:"threshold"`
	AIModel              string    `json:"ai_model,omitempty"`
	AIError              string    `json:"ai_error,omitempty"`
	AnalysisMode         string    `json:"analysis_mode,omitempty"`
	AnalysisScope        string    `json:"analysis_scope,omitempty"`
	PlatformAnalysisMode string    `json:"platform_analysis_mode,omitempty"`
	PlatformAutoBlock    bool      `json:"platform_auto_block"`
	AFEnabled            bool      `json:"af_enabled"`
	AFError              string    `json:"af_error,omitempty"`
}
type DefenseWorker struct {
	config       Config
	store        *Store
	client       *http.Client
	mu           sync.Mutex
	state        DefenseStatus
	controllerAt time.Time
}

func newDefense(config Config, store *Store) *DefenseWorker {
	return &DefenseWorker{config: config, store: store, client: newHTTPClient(12 * time.Second), state: DefenseStatus{Enabled: config.Defense.Enabled, LivelogURL: config.Defense.LivelogURL}}
}
func (d *DefenseWorker) status() DefenseStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	state := d.state
	_ = d.store.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket([]byte("counts")).Get([]byte("defense_sent")); len(v) == 8 {
			state.Submitted = binary.BigEndian.Uint64(v)
		}
		state.Pending = uint64(tx.Bucket([]byte("defense_pending")).Stats().KeyN)
		return nil
	})
	return state
}
func (d *DefenseWorker) request(ctx context.Context, endpoint string, body any, target any, authenticated bool) error {
	var reader io.Reader
	method := http.MethodGet
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return errors.New("防护接口地址无效")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		req.Header.Set("X-Agent-ID", d.config.Defense.AgentID)
		req.Header.Set("Authorization", "Bearer "+d.config.Defense.Token)
	}
	response, err := d.client.Do(req)
	if err != nil {
		return errors.New("无法连接 Livelog；已保留待送审队列并等待重试")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("Livelog 返回 HTTP %d；未确认送审或封禁成功", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
	if err != nil || len(raw) > 2*1024*1024 || json.Unmarshal(raw, target) != nil {
		return errors.New("Livelog 响应无效；保留原状态重试")
	}
	return nil
}

func defenseEventID(agent string, e Entry) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", agent, e.ID, e.RawSHA256)))
	return hex.EncodeToString(h[:16])
}

func defenseRaw(e Entry) (string, error) {
	payload, err := aiPayload([]Entry{e})
	if err != nil {
		return "", err
	}
	var prepared struct {
		Requests []map[string]any `json:"untrusted_requests"`
	}
	if err = json.Unmarshal(payload, &prepared); err != nil || len(prepared.Requests) != 1 {
		return "", errors.New("无法准备脱敏正文")
	}
	row := prepared.Requests[0]
	hash := sha256.Sum256([]byte(e.Body))
	text, _ := json.Marshal(row["body"])
	truncated := row["body_truncated"] == true || len([]rune(string(text))) > 6000 || len(e.URI) > 1600
	body := row["body"]
	if truncated {
		body = runePrefix(string(text), 6000)
	}
	raw := map[string]any{"time": e.Time, "ip": e.IP, "method": e.Method, "request": fmt.Sprintf("%s %s HTTP/1.1", e.Method, runePrefix(redactURI(e.URI), 1600)), "status": e.Status,
		"content_type": e.ContentType, "decoded_body": body, "decode_state": e.Decoded.State, "decode_format": e.Decoded.Format, "decode_message": e.Decoded.Message,
		"body_unresolved": e.Decoded.Unresolved, "body_truncated": truncated, "body_sha256": hex.EncodeToString(hash[:]), "raw_sha256": e.RawSHA256, "lovelylog_id": e.ID}
	// Keep serialized JSON intact while meeting the receiver's per-record bound.
	for limit := 5000; limit >= 0; limit -= 1000 {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return "", err
		}
		if len(encoded) <= 16384 {
			return string(encoded), nil
		}
		raw["decoded_body"] = runePrefix(string(text), limit)
		raw["body_truncated"] = true
	}
	return "", errors.New("送审元数据超过接收端限制")
}

func (d *DefenseWorker) queued() ([]Entry, error) {
	entries := []Entry{}
	err := d.store.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		last := meta.Get([]byte("defense_cursor:" + d.config.Defense.AgentID))
		cursor := tx.Bucket([]byte("entries")).Cursor()
		k, v := cursor.First()
		if len(last) == 8 {
			k, v = cursor.Seek(last)
			if bytes.Equal(k, last) {
				k, v = cursor.Next()
			}
		}
		for ; k != nil && len(entries) < 30; k, v = cursor.Next() {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			entries = append(entries, e)
		}
		return nil
	})
	return entries, err
}
func (d *DefenseWorker) submit(ctx context.Context) (int, error) {
	entries, err := d.queued()
	if err != nil || len(entries) == 0 {
		return 0, err
	}
	events := []map[string]any{}
	for _, e := range entries {
		raw, err := defenseRaw(e)
		if err != nil {
			return 0, err
		}
		events = append(events, map[string]any{"eventId": defenseEventID(d.config.Defense.AgentID, e), "kind": "access.log", "source": d.config.LogPath, "raw": raw, "collectedAt": float64(e.Received.UnixMilli()) / 1000})
	}
	var ack struct {
		Accepted int `json:"accepted"`
	}
	if err = d.request(ctx, d.config.Defense.HubURL+"/v1/ingest", map[string]any{"events": events, "metadata": map[string]any{"hostname": "LovelyLog", "version": "1.2.1"}}, &ack, true); err != nil {
		return 0, err
	}
	if ack.Accepted != len(entries) {
		return 0, errors.New("Livelog 未确认全部请求；使用相同编号重试")
	}
	now := time.Now()
	err = d.store.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("entries"))
		pending := tx.Bucket([]byte("defense_pending"))
		for _, e := range entries {
			// Read again so a manual re-decode cannot be overwritten by an older snapshot.
			var current Entry
			if err := json.Unmarshal(b.Get(numberKey(e.ID)), &current); err != nil {
				return err
			}
			current.Defense = &DefenseReceipt{EventID: defenseEventID(d.config.Defense.AgentID, e), AIState: "pending", SentAt: now, DecodedSHA256: e.Decoded.SHA256}
			value, err := json.Marshal(current)
			if err != nil {
				return err
			}
			if err = b.Put(numberKey(e.ID), value); err != nil {
				return err
			}
			if err = pending.Put(numberKey(e.ID), []byte(current.Defense.EventID)); err != nil {
				return err
			}
		}
		if err := adjustCount(tx, "defense_sent", int64(len(entries))); err != nil {
			return err
		}
		return tx.Bucket([]byte("meta")).Put([]byte("defense_cursor:"+d.config.Defense.AgentID), numberKey(entries[len(entries)-1].ID))
	})
	if err == nil {
		d.mu.Lock()
		d.state.LastSent = now
		d.mu.Unlock()
	}
	return len(entries), err
}

func (d *DefenseWorker) refreshReceipts(ctx context.Context) error {
	ids := map[string]uint64{}
	err := d.store.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket([]byte("defense_pending")).Cursor()
		for k, v := cursor.First(); k != nil && len(ids) < 50; k, v = cursor.Next() {
			ids[string(v)] = binary.BigEndian.Uint64(k)
		}
		cursor = tx.Bucket([]byte("entries")).Cursor()
		for k, v := cursor.Last(); k != nil && len(ids) < 100; k, v = cursor.Prev() {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			if e.Defense != nil {
				ids[e.Defense.EventID] = e.ID
			} else {
				break
			}
		}
		return nil
	})
	if err != nil || len(ids) == 0 {
		return err
	}
	keys := []string{}
	for key := range ids {
		keys = append(keys, key)
	}
	var response struct {
		Events []DefenseReceipt `json:"events"`
	}
	if err = d.request(ctx, d.config.Defense.HubURL+"/v1/verdicts", map[string]any{"eventIds": keys}, &response, true); err != nil {
		return err
	}
	return d.store.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("entries"))
		for _, receipt := range response.Events {
			id, ok := ids[receipt.EventID]
			if !ok {
				return errors.New("Livelog 返回了未请求的记录编号")
			}
			var e Entry
			if err := json.Unmarshal(b.Get(numberKey(id)), &e); err != nil {
				return err
			}
			if e.Defense == nil || e.Defense.EventID != receipt.EventID {
				continue
			}
			receipt.SentAt = e.Defense.SentAt
			receipt.DecodedSHA256 = e.Defense.DecodedSHA256
			receipt.CheckedAt = time.Now()
			e.Defense = &receipt
			value, err := json.Marshal(e)
			if err != nil {
				return err
			}
			if err = b.Put(numberKey(id), value); err != nil {
				return err
			}
			if receipt.AIState != "pending" && receipt.AIState != "unknown" {
				if err = tx.Bucket([]byte("defense_pending")).Delete(numberKey(id)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (d *DefenseWorker) controller(ctx context.Context) error {
	var ai struct {
		Settings struct {
			Enabled              bool    `json:"enabled"`
			AutoBlock            bool    `json:"autoBlock"`
			Threshold            float64 `json:"threshold"`
			Model                string  `json:"model"`
			LastError            string  `json:"lastError"`
			AnalysisMode         string  `json:"analysisMode"`
			AnalysisScope        string  `json:"analysisScope"`
			PlatformAnalysisMode string  `json:"platformAnalysisMode"`
			PlatformAutoBlock    bool    `json:"platformAutoBlock"`
		} `json:"settings"`
		AnalysisScope        string `json:"analysisScope"`
		PlatformAnalysisMode string `json:"platformAnalysisMode"`
	}
	if err := d.request(ctx, d.config.Defense.LivelogURL+"/api/ai?source=agent&agent="+url.QueryEscape(d.config.Defense.AgentID)+"&pageSize=20", nil, &ai, false); err != nil {
		return err
	}
	var af struct {
		Settings struct {
			Enabled bool `json:"enabled"`
		} `json:"settings"`
		Status struct {
			Error string `json:"error"`
		} `json:"status"`
	}
	if err := d.request(ctx, d.config.Defense.LivelogURL+"/api/af", nil, &af, false); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state.AIEnabled = ai.Settings.Enabled && ai.Settings.AnalysisMode != "local"
	d.state.AutoBlock = ai.Settings.AutoBlock
	d.state.Threshold = ai.Settings.Threshold
	d.state.AIModel = ai.Settings.Model
	d.state.AIError = ai.Settings.LastError
	d.state.AnalysisMode = ai.Settings.AnalysisMode
	d.state.AnalysisScope = ai.Settings.AnalysisScope
	if d.state.AnalysisScope == "" {
		d.state.AnalysisScope = ai.AnalysisScope
	}
	d.state.PlatformAnalysisMode = ai.Settings.PlatformAnalysisMode
	d.state.PlatformAutoBlock = ai.Settings.PlatformAutoBlock
	if d.state.PlatformAnalysisMode == "" {
		d.state.PlatformAnalysisMode = ai.PlatformAnalysisMode
	}
	d.state.AFEnabled = af.Settings.Enabled
	d.state.AFError = af.Status.Error
	d.controllerAt = time.Now()
	return nil
}
func (d *DefenseWorker) once(ctx context.Context) (n int, err error) {
	defer func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.state.Connected = err == nil
		d.state.CheckedAt = time.Now()
		d.state.Error = ""
		if err != nil {
			d.state.Error = err.Error()
		}
	}()
	if d.config.AnalysisMode == "local" {
		if time.Since(d.controllerAt) > 15*time.Second {
			if err = d.controller(ctx); err != nil {
				return 0, err
			}
		}
		d.mu.Lock()
		manualLocal := d.state.AnalysisMode == "local" && !d.state.AutoBlock
		d.mu.Unlock()
		if !manualLocal {
			return 0, errors.New("LovelyLog 来源尚未在 Livelog 切换为本地检测及仅人工封禁，已暂停送审并保留队列")
		}
	}
	n, err = d.submit(ctx)
	if err == nil {
		err = d.refreshReceipts(ctx)
	}
	if err == nil && time.Since(d.controllerAt) > 15*time.Second {
		err = d.controller(ctx)
	}
	return n, err
}
func (d *DefenseWorker) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			n, err := d.once(ctx)
			delay := 3 * time.Second
			if err != nil {
				delay = 10 * time.Second
			} else if n == 30 {
				delay = 250 * time.Millisecond
			}
			timer.Reset(delay)
		}
	}
}
