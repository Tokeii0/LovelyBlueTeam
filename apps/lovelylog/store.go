package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

type Entry struct {
	ID          uint64          `json:"id"`
	Time        string          `json:"time"`
	Received    time.Time       `json:"received"`
	IP          string          `json:"ip"`
	Method      string          `json:"method"`
	URI         string          `json:"uri"`
	ContentType string          `json:"content_type"`
	Status      int             `json:"status"`
	Upstream    string          `json:"upstream"`
	Duration    string          `json:"duration"`
	Body        string          `json:"body,omitempty"`
	Raw         string          `json:"raw,omitempty"`
	RawSHA256   string          `json:"raw_sha256"`
	Decoded     Decoded         `json:"decoded"`
	Findings    []Finding       `json:"findings"`
	AIReport    string          `json:"ai_report,omitempty"`
	AIModel     string          `json:"ai_model,omitempty"`
	AIAt        time.Time       `json:"ai_at,omitempty"`
	AIRevision  uint64          `json:"ai_revision,omitempty"`
	LocalReport string          `json:"local_report,omitempty"`
	LocalAt     time.Time       `json:"local_at,omitempty"`
	Generation  int             `json:"generation"`
	SourceEnd   int64           `json:"source_end"`
	Defense     *DefenseReceipt `json:"defense,omitempty"`
}

type ReadCursor struct {
	Offset     int64  `json:"offset"`
	Anchor     []byte `json:"anchor"`
	Partial    []byte `json:"partial"`
	Generation int    `json:"generation"`
}

type Store struct{ db *bolt.DB }

func openStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"entries", "meta", "counts", "defense_pending", "analysis_cache"} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db}, nil
}

func numberKey(id uint64) []byte {
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], id)
	return key[:]
}

func (s *Store) cursor(source string) (*ReadCursor, error) {
	var cursor *ReadCursor
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket([]byte("meta")).Get([]byte(source))
		if data == nil {
			return nil
		}
		cursor = &ReadCursor{}
		return json.Unmarshal(data, cursor)
	})
	return cursor, err
}

func adjustCount(tx *bolt.Tx, name string, delta int64) error {
	b := tx.Bucket([]byte("counts"))
	current := uint64(0)
	if value := b.Get([]byte(name)); len(value) == 8 {
		current = binary.BigEndian.Uint64(value)
	}
	if delta < 0 && current < uint64(-delta) {
		return errors.New("本地计数不一致")
	}
	return b.Put([]byte(name), numberKey(uint64(int64(current)+delta)))
}

func (s *Store) commit(source string, cursor ReadCursor, entries []Entry) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("entries"))
		for _, entry := range entries {
			id, err := b.NextSequence()
			if err != nil {
				return err
			}
			entry.ID = id
			data, err := json.Marshal(entry)
			if err != nil {
				return err
			}
			if err = b.Put(numberKey(id), data); err != nil {
				return err
			}
			if err = adjustCount(tx, "total", 1); err != nil {
				return err
			}
			if err = adjustCount(tx, entry.Decoded.State, 1); err != nil {
				return err
			}
		}
		data, err := json.Marshal(cursor)
		if err != nil {
			return err
		}
		// Logs and the exact byte cursor commit in the same transaction.
		return tx.Bucket([]byte("meta")).Put([]byte(source), data)
	})
}

func (s *Store) entry(id uint64) (Entry, error) {
	var entry Entry
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket([]byte("entries")).Get(numberKey(id))
		if data == nil {
			return errors.New("日志记录不存在")
		}
		return json.Unmarshal(data, &entry)
	})
	if err == nil {
		entry.Findings = localFindings(entry)
	}
	return entry, err
}

func (s *Store) updateEntry(id uint64, change func(*Entry)) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("entries"))
		data := b.Get(numberKey(id))
		if data == nil {
			return errors.New("日志记录不存在")
		}
		var entry Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			return err
		}
		oldState := entry.Decoded.State
		change(&entry)
		if oldState != entry.Decoded.State {
			if err := adjustCount(tx, oldState, -1); err != nil {
				return err
			}
			if err := adjustCount(tx, entry.Decoded.State, 1); err != nil {
				return err
			}
		}
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put(numberKey(id), data)
	})
}

type AnalysisReport struct {
	Report string    `json:"report"`
	Model  string    `json:"model"`
	At     time.Time `json:"at"`
}

func (s *Store) cachedAnalysis(key string) (AnalysisReport, bool, error) {
	var report AnalysisReport
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket([]byte("analysis_cache")).Get([]byte(key))
		if data == nil {
			return nil
		}
		if err := json.Unmarshal(data, &report); err != nil {
			return err
		}
		found = strings.TrimSpace(report.Report) != ""
		return nil
	})
	return report, found, err
}

func (s *Store) saveAnalysis(key string, report AnalysisReport, entries []Entry) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("entries"))
		for _, original := range entries {
			var entry Entry
			if err := json.Unmarshal(b.Get(numberKey(original.ID)), &entry); err != nil {
				return err
			}
			entry.AIReport, entry.AIModel, entry.AIAt = report.Report, report.Model, report.At
			data, err := json.Marshal(entry)
			if err != nil {
				return err
			}
			if err = b.Put(numberKey(entry.ID), data); err != nil {
				return err
			}
		}
		data, err := json.Marshal(report)
		if err != nil {
			return err
		}
		return tx.Bucket([]byte("analysis_cache")).Put([]byte(key), data)
	})
}

type Query struct {
	Before      uint64
	Text, State string
	Limit       int
	Suspicious  bool
}
type Page struct {
	Entries []Entry `json:"entries"`
	Before  uint64  `json:"before"`
	HasMore bool    `json:"has_more"`
	Scanned int     `json:"scanned"`
}

func (s *Store) list(q Query) (Page, error) {
	page := Page{Entries: []Entry{}}
	err := s.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket([]byte("entries")).Cursor()
		k, v := cursor.Last()
		if q.Before > 0 {
			k, v = cursor.Seek(numberKey(q.Before))
			if k == nil {
				k, v = cursor.Last()
			} else {
				k, v = cursor.Prev()
			}
		}
		needle := strings.ToLower(q.Text)
		for k != nil && page.Scanned < 20000 {
			var entry Entry
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}
			page.Scanned++
			page.Before = entry.ID
			matches := (q.State == "" || q.State == entry.Decoded.State) &&
				(needle == "" || strings.Contains(strings.ToLower(entry.Raw+"\n"+entry.Decoded.Text), needle))
			if matches {
				entry.Findings = localFindings(entry)
			}
			if matches && (!q.Suspicious || len(entry.Findings) > 0) {
				entry.Raw, entry.Body = "", ""
				entry.Decoded.Text = runePrefix(redactedBody(entry.Decoded.Text), 180)
				entry.AIReport = runePrefix(entry.AIReport, 120)
				entry.LocalReport = runePrefix(entry.LocalReport, 120)
				page.Entries = append(page.Entries, entry)
			}
			k, v = cursor.Prev()
			if len(page.Entries) >= q.Limit {
				break
			}
		}
		page.HasMore = k != nil
		return nil
	})
	return page, err
}

func (s *Store) counts() map[string]uint64 {
	result := map[string]uint64{}
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("counts")).ForEach(func(k, v []byte) error {
			if len(v) == 8 {
				result[string(k)] = binary.BigEndian.Uint64(v)
			}
			return nil
		})
	})
	return result
}

func runePrefix(value string, n int) string {
	runes := []rune(value)
	if len(runes) <= n {
		return value
	}
	return string(runes[:n]) + "…（已截断）"
}
