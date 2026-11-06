package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExactBackendPlaintextLookupAndIntegrity(t *testing.T) {
	ciphertext := "ciphertext-from-a-backend-request"
	h := sha256.Sum256([]byte(ciphertext))
	plain := `{"body_content":"{\"query\":\"union select 1\"}"}`
	ph := sha256.Sum256([]byte(plain))
	file := filepath.Join(t.TempDir(), "known.json")
	index := map[string]KnownPlaintext{hex.EncodeToString(h[:]): {Plaintext: plain, PlaintextSHA256: hex.EncodeToString(ph[:]), Source: "backend.log:1 -> backend.log:2"}}
	data, _ := json.Marshal(index)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	p := CryptoProfile{Name: "backend fixture", PathRegex: `^/business`, Mode: "BACKEND-LOG", LookupFile: file}
	if err := p.prepare(); err != nil {
		t.Fatal(err)
	}
	d := decodeBody(`{"body":"`+ciphertext+`"}`, "/business", []CryptoProfile{p})
	if d.State != "restored" || d.Unresolved != 0 || !strings.Contains(d.Text, "union select 1") {
		t.Fatalf("known plaintext not reconstructed: %s", d.State)
	}
	matched := false
	for _, f := range d.Fields {
		if f.Path == "$.body" && f.State == "restored" && f.Source != "" {
			matched = true
		}
	}
	if !matched {
		t.Fatal("missing association provenance")
	}
	d = decodeBody(`{"head":{"encrypt_type":"AES"},"body":"a-different-ciphertext"}`, "/business", []CryptoProfile{p})
	if d.State != "encrypted" || strings.Contains(d.Text, "union select 1") {
		t.Fatal("a different ciphertext was filled with unrelated historical plaintext")
	}
	item := index[hex.EncodeToString(h[:])]
	item.Plaintext = "tampered"
	index[hex.EncodeToString(h[:])] = item
	data, _ = json.Marshal(index)
	_ = os.WriteFile(file, data, 0600)
	if p.prepare() == nil {
		t.Fatal("plaintext index integrity check missing")
	}
}

func TestKeyMetadataNeverContainsFileContents(t *testing.T) {
	file := filepath.Join(t.TempDir(), "fixture.pem")
	content := strings.Repeat("private-secret-value", 10)
	_ = os.WriteFile(file, []byte(content), 0600)
	info := inspectKeyFile(file)
	data, _ := json.Marshal(info)
	if strings.Contains(string(data), "private-secret-value") || info.Format != "unrecognized" {
		t.Fatal("unrecognized key contents exposed")
	}
}
