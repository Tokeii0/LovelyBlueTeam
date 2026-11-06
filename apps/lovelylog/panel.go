package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const readChunk = 1024 * 1024

var errRange = errors.New("日志已轮转或清空")
var rangePattern = regexp.MustCompile(`^bytes (\d+)-(\d+)/(\d+)$`)

type PanelClient struct {
	config Config
	client *http.Client
}
type Segment struct {
	Data        []byte
	Start, Size int64
}

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (p *PanelClient) read(ctx context.Context, rangeHeader string) (Segment, error) {
	var part Segment
	endpoint := p.config.PanelURL + p.config.PanelPrefix + "/files/download?" + url.Values{"path": {p.config.LogPath}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return part, err
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	token := md5.Sum([]byte("1panel" + p.config.PanelKey + timestamp))
	req.Header.Set("1Panel-Token", hex.EncodeToString(token[:]))
	req.Header.Set("1Panel-Timestamp", timestamp)
	req.Header.Set("Range", rangeHeader)
	req.Header.Set("Accept-Encoding", "identity")
	response, err := p.client.Do(req)
	if err != nil {
		return part, errors.New("无法读取 1Panel：检查网络、API 地址与超时")
	}
	defer response.Body.Close()
	if response.StatusCode == 416 {
		if response.Header.Get("Content-Range") == "bytes */0" {
			return part, nil
		}
		return part, errRange
	}
	if response.StatusCode != 206 && response.StatusCode != 200 {
		return part, fmt.Errorf("1Panel 读取失败（HTTP %d），检查权限和日志路径", response.StatusCode)
	}
	if response.StatusCode == 206 {
		m := rangePattern.FindStringSubmatch(response.Header.Get("Content-Range"))
		if m == nil {
			return part, errors.New("1Panel 返回了无效的 Content-Range")
		}
		start, e1 := strconv.ParseInt(m[1], 10, 64)
		end, e2 := strconv.ParseInt(m[2], 10, 64)
		size, e3 := strconv.ParseInt(m[3], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || end < start || end >= size || end-start+1 > maxPlaintext {
			return part, errors.New("日志分段长度无效")
		}
		part.Start, part.Size = start, size
		part.Data, err = io.ReadAll(io.LimitReader(response.Body, end-start+2))
		if err != nil || int64(len(part.Data)) != end-start+1 {
			return Segment{}, errors.New("日志分段未完整传输，将保留读取位置重试")
		}
	} else {
		if strings.Contains(response.Header.Get("Content-Type"), "application/json") || strings.Contains(response.Header.Get("Content-Type"), "text/html") {
			return part, errors.New("1Panel 返回接口错误内容，未作为日志接收")
		}
		part.Data, err = io.ReadAll(io.LimitReader(response.Body, maxPlaintext+1))
		if err != nil || len(part.Data) > maxPlaintext {
			return Segment{}, errors.New("面板未正确支持 Range 或响应过大")
		}
		part.Size = int64(len(part.Data))
		if strings.HasPrefix(rangeHeader, "bytes=") && !strings.HasPrefix(rangeHeader, "bytes=-") {
			startText, endText, _ := strings.Cut(strings.TrimPrefix(rangeHeader, "bytes="), "-")
			start, _ := strconv.ParseInt(startText, 10, 64)
			end, _ := strconv.ParseInt(endText, 10, 64)
			if start > part.Size {
				return Segment{}, errRange
			}
			end = min(end+1, part.Size)
			if end < start {
				return Segment{}, errRange
			}
			part.Data, part.Start = part.Data[start:end], start
		}
	}
	return part, nil
}

type Collector struct {
	config    Config
	panel     *PanelClient
	store     *Store
	source    string
	runMu     sync.Mutex
	mu        sync.Mutex
	checked   time.Time
	lastError string
	added     int
	fileSize  int64
	rotated   bool
}

func newCollector(config Config, store *Store) *Collector {
	hash := sha256.Sum256([]byte(config.PanelURL + config.PanelPrefix + config.LogPath))
	return &Collector{config: config, store: store, panel: &PanelClient{config, newHTTPClient(15 * time.Second)}, source: "cursor:" + hex.EncodeToString(hash[:])}
}

func (c *Collector) once(ctx context.Context) (int, error) {
	c.runMu.Lock()
	defer c.runMu.Unlock()
	count, err := c.collect(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checked, c.added = time.Now(), count
	c.lastError = ""
	if err != nil {
		c.lastError = err.Error()
	}
	return count, err
}

func (c *Collector) collect(ctx context.Context) (int, error) {
	cursor, err := c.store.cursor(c.source)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	c.rotated = false
	c.mu.Unlock()
	if cursor == nil {
		window := readChunk
		var segment Segment
		for {
			segment, err = c.panel.read(ctx, fmt.Sprintf("bytes=-%d", window))
			if err != nil {
				return 0, err
			}
			if segment.Start == 0 || bytes.Count(segment.Data, []byte{'\n'}) > c.config.InitialLines || window == maxPlaintext {
				break
			}
			window = min(window*2, maxPlaintext)
		}
		data := segment.Data
		if segment.Start > 0 {
			pos := bytes.IndexByte(data, '\n')
			if pos < 0 {
				return 0, errors.New("末尾单条日志超过 8 MB，未建立不完整基线")
			}
			data = data[pos+1:]
		}
		parts := bytes.Split(data, []byte{'\n'})
		partial := bytes.Clone(parts[len(parts)-1])
		parts = parts[:len(parts)-1]
		if len(parts) > c.config.InitialLines {
			parts = parts[len(parts)-c.config.InitialLines:]
		}
		cursor = &ReadCursor{Offset: segment.Start + int64(len(segment.Data)), Anchor: bytes.Clone(segment.Data[max(0, len(segment.Data)-64):]), Partial: partial}
		entries := c.entries(parts, *cursor)
		c.mu.Lock()
		c.fileSize = segment.Size
		c.mu.Unlock()
		return len(entries), c.store.commit(c.source, *cursor, entries)
	}
	count := 0
	for tick := 0; tick < 4; tick++ {
		start := max(int64(0), cursor.Offset-int64(len(cursor.Anchor)))
		segment, err := c.panel.read(ctx, fmt.Sprintf("bytes=%d-%d", start, start+readChunk-1))
		if err != nil && !errors.Is(err, errRange) {
			return count, err
		}
		if errors.Is(err, errRange) || segment.Size < cursor.Offset || segment.Start != start || !bytes.HasPrefix(segment.Data, cursor.Anchor) {
			segment, err = c.panel.read(ctx, fmt.Sprintf("bytes=0-%d", readChunk-1))
			if err != nil {
				return count, err
			}
			cursor = &ReadCursor{Generation: cursor.Generation + 1}
			c.mu.Lock()
			c.rotated = true
			c.mu.Unlock()
		}
		fresh := segment.Data[len(cursor.Anchor):]
		joined := append(bytes.Clone(cursor.Partial), fresh...)
		parts := bytes.Split(joined, []byte{'\n'})
		partial := bytes.Clone(parts[len(parts)-1])
		parts = parts[:len(parts)-1]
		if len(partial) > maxPlaintext {
			return count, errors.New("单条日志超过 8 MB，读取已暂停，位置未推进")
		}
		cursor.Offset = segment.Start + int64(len(segment.Data))
		cursor.Anchor, cursor.Partial = bytes.Clone(segment.Data[max(0, len(segment.Data)-64):]), partial
		entries := c.entries(parts, *cursor)
		if err := c.store.commit(c.source, *cursor, entries); err != nil {
			return count, err
		}
		count += len(entries)
		c.mu.Lock()
		c.fileSize = segment.Size
		c.mu.Unlock()
		if cursor.Offset >= segment.Size || len(fresh) == 0 {
			break
		}
	}
	return count, nil
}

func logValue(data map[string]json.RawMessage, name string) string {
	value := data[name]
	var text string
	if json.Unmarshal(value, &text) == nil {
		return text
	}
	if string(value) == "null" {
		return ""
	}
	return string(value)
}

func makeEntry(raw string, profiles []CryptoProfile) Entry {
	hash := sha256.Sum256([]byte(raw))
	e := Entry{Received: time.Now(), Raw: raw, RawSHA256: hex.EncodeToString(hash[:])}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil || fields == nil {
		e.Decoded = Decoded{State: "failed", Message: "该行不是完整有效的 Nginx JSON 日志，原文已保留"}
		e.Findings = []Finding{}
		return e
	}
	e.Time, e.IP, e.Method, e.URI = logValue(fields, "time"), logValue(fields, "ip"), logValue(fields, "method"), logValue(fields, "uri")
	if e.IP == "" {
		e.IP = logValue(fields, "remote_addr")
	}
	if e.URI == "" {
		e.URI = logValue(fields, "request_uri")
	}
	e.ContentType, e.Body = logValue(fields, "content_type"), logValue(fields, "body")
	e.Upstream, e.Duration = logValue(fields, "upstream"), logValue(fields, "duration")
	e.Status, _ = strconv.Atoi(logValue(fields, "status"))
	e.Decoded = decodeBody(e.Body, e.URI, profiles)
	e.Findings = localFindings(e)
	return e
}

func (c *Collector) entries(lines [][]byte, cursor ReadCursor) []Entry {
	entries := make([]Entry, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		e := makeEntry(string(bytes.TrimSuffix(line, []byte{'\r'})), c.config.Profiles)
		e.Generation, e.SourceEnd = cursor.Generation, cursor.Offset
		entries = append(entries, e)
	}
	return entries
}

func (c *Collector) status() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]any{"checked_at": c.checked, "error": c.lastError, "last_added": c.added, "file_bytes": c.fileSize, "rotated": c.rotated, "log_path": c.config.LogPath}
}
