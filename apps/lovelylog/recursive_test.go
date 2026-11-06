package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecursiveBodyAndBodyContent(t *testing.T) {
	p := testProfile(t)
	inner := encryptFixture(t, p, []byte(`{"q":"union select 1","patient_id":"patient-secret"}`))
	outer, _ := json.Marshal(map[string]any{"body_content": inner, "unchanged": "normal"})
	root, _ := json.Marshal(map[string]any{"head": map[string]any{"encrypt_type": "AES"}, "body": encryptFixture(t, p, outer)})
	d := decodeBody(string(root), "/encrypted", []CryptoProfile{p})
	if d.State != "decrypted" || d.Unresolved != 0 || !strings.Contains(d.Text, "union select 1") {
		t.Fatalf("nested AES not recovered: %s %s", d.State, d.Message)
	}
	paths := map[string]bool{}
	for _, field := range d.Fields {
		if field.State == "decrypted" {
			paths[field.Path] = true
		}
	}
	if !paths["$.body"] || !paths["$.body.body_content"] {
		t.Fatalf("missing field paths: %v", paths)
	}
	data, err := aiPayload([]Entry{{Decoded: d}})
	if err != nil || strings.Contains(string(data), "patient-secret") || !strings.Contains(string(data), "union select 1") {
		t.Fatal("nested plaintext must be redacted without erasing attack evidence")
	}
}

func TestRecursiveUnknownFieldsAreNotReportedAsPlain(t *testing.T) {
	p := testProfile(t)
	unknown := base64.StdEncoding.EncodeToString(make([]byte, 64))
	// Non-UTF8 ciphertext with no outer encrypt_type must still be detected inside body_content.
	unknown = base64.StdEncoding.EncodeToString(append([]byte{255}, make([]byte, 63)...))
	d := decodeBody(`{"head":{"method":"normal"},"body":{"body_content":"`+unknown+`"}}`, "/business", nil)
	if d.State != "encrypted" || d.Unresolved != 1 || strings.Contains(d.Text, unknown) {
		t.Fatalf("opaque nested field silently accepted: %s", d.State)
	}
	good := encryptFixture(t, p, []byte(`{"body_content":"`+unknown+`"}`))
	// A profile restricted to $.body leaves the unrelated inner ciphertext unresolved.
	p.Field = "body"
	d = decodeBody(`{"body":"`+good+`"}`, "/encrypted", []CryptoProfile{p})
	if d.State != "partial" || d.Unresolved != 1 {
		t.Fatalf("partial recovery incorrectly classified: %s", d.State)
	}
}

func TestStructuredEncodingAndRecursiveLimits(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte(`{"query":"中文+plus","nested":{"body_content":"{\"ok\":true}"}}`))
	d := decodeBody(`{"body":"`+body+`"}`, "/a", nil)
	if d.State != "decoded" || !strings.Contains(d.Text, "中文+plus") || !strings.Contains(d.Text, `"ok": true`) {
		t.Fatal("encoding expansion failed")
	}
	d = decodeBody(`{"body_content":"%257B%2522q%2522%253A%2522a%252Bb%2522%257D"}`, "/a", nil)
	if !strings.Contains(d.Text, "a+b") || d.State != "decoded" {
		t.Fatal("double URL encoding failed or plus was lost")
	}
	d = decodeBody(strings.Repeat(`{"x":`, 30)+`0`+strings.Repeat("}", 30), "/a", nil)
	if d.State != "partial" {
		t.Fatal("recursive depth bound missing")
	}
}

func hybridFixture(t *testing.T, p CryptoProfile, key *rsa.PrivateKey, text string) string {
	t.Helper()
	aeskey := make([]byte, 32)
	nonce := make([]byte, 12)
	_, _ = rand.Read(aeskey)
	_, _ = rand.Read(nonce)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, aeskey, nil)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(aeskey)
	gcm, _ := cipher.NewGCM(block)
	sealed := gcm.Seal(nil, nonce, []byte(text), nil)
	parts := [][]byte{wrapped, nonce, sealed[len(sealed)-16:], sealed[:len(sealed)-16]}
	encoded := []string{}
	for _, part := range parts {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(part))
	}
	return strings.Join(encoded, ".")
}

func TestHybridGCMAuthenticationAndPrivateKeyFormats(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.pem")
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	p := CryptoProfile{Name: "hybrid fixture", PathRegex: `^/business`, Mode: "RSA-AES-GCM", PrivateKeyFile: path}
	if err = p.prepare(); err != nil {
		t.Fatal(err)
	}
	value := hybridFixture(t, p, key, `{"body_content":"{\"cmd\":\"cmd /c whoami\"}"}`)
	d := decodeBody(`{"body":"`+value+`"}`, "/business", []CryptoProfile{p})
	if d.State != "decrypted" || !strings.Contains(d.Text, "whoami") {
		t.Fatalf("GCM recovery failed: %s", d.Message)
	}
	parts := strings.Split(value, ".")
	tag, _ := base64.StdEncoding.DecodeString(parts[2])
	tag[0] ^= 1
	parts[2] = base64.StdEncoding.EncodeToString(tag)
	d = decodeBody(`{"body_content":"`+strings.Join(parts, ".")+`"}`, "/business", []CryptoProfile{p})
	if d.State != "failed" || strings.Contains(d.Text, "whoami") || d.Unresolved != 1 {
		t.Fatal("tampered GCM data must never produce confirmed plaintext")
	}
	d = decodeBody(`{"body":"`+value+`"}`, "/business", nil)
	if d.State != "encrypted" || d.Fields[len(d.Fields)-1].Format != "hybrid-envelope" {
		t.Fatal("four-part ciphertext without a matching key must stay unavailable")
	}
	if err = os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(make([]byte, 176))), 0600); err != nil {
		t.Fatal(err)
	}
	if err = p.prepare(); err == nil {
		t.Fatal("nonstandard encrypted file must not be accepted as RSA private key")
	}
}
