package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testProfile(t *testing.T) CryptoProfile {
	t.Helper()
	p := CryptoProfile{Name: "fixture", PathRegex: `^/encrypted`, Mode: "AES-CBC", KeyBase64: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")), IVBase64: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))}
	if err := p.prepare(); err != nil {
		t.Fatal(err)
	}
	return p
}

func encryptFixture(t *testing.T, p CryptoProfile, data []byte) string {
	t.Helper()
	n := aes.BlockSize - len(data)%aes.BlockSize
	padded := append(bytes.Clone(data), bytes.Repeat([]byte{byte(n)}, n)...)
	block, err := aes.NewCipher(p.key)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, p.iv).CryptBlocks(encrypted, padded)
	return base64.StdEncoding.EncodeToString(encrypted)
}

func TestCBCAndStrictPadding(t *testing.T) {
	p := testProfile(t)
	text := `{"message":"中文","q":"union select 1"}`
	d := decodeBody(encryptFixture(t, p, []byte(text)), "/encrypted", []CryptoProfile{p})
	if d.State != "decrypted" || !strings.Contains(d.Text, "中文") || d.Format != "json" {
		t.Fatalf("unexpected result state %s / %s", d.State, d.Message)
	}
	for _, data := range [][]byte{nil, {0}, bytes.Repeat([]byte{0}, 16), append(bytes.Repeat([]byte{'x'}, 14), 1, 2)} {
		if _, err := unpadPKCS7(data, 16); err == nil {
			t.Fatal("accepted invalid padding")
		}
	}
	bad := decodeBody("not-base64!", "/encrypted", []CryptoProfile{p})
	if bad.State != "failed" {
		t.Fatal("wrong ciphertext must stay failed")
	}
	if d := decodeBody(`{"head":{"encrypt_type":"AES"},"body":"aGVsbG8="}`, "/business", []CryptoProfile{p}); d.State != "encrypted" || d.Profile != "" {
		t.Fatal("JSP key must not be guessed for a business request")
	}
}

func TestJSONFieldAndWrapper(t *testing.T) {
	p := testProfile(t)
	encoded := encryptFixture(t, p, []byte(`{"ok":true}`))
	p.Field = "body.payload"
	p.PrefixBytes = 2
	p.SuffixBytes = 3
	body, _ := json.Marshal(map[string]any{"body": map[string]any{"payload": "xx" + encoded + "zzz"}})
	if d := decodeBody(string(body), "/encrypted", []CryptoProfile{p}); d.State != "decrypted" {
		t.Fatal(d.Message)
	}
	if _, err := p.decrypt(`{"body":{"payload":{}}}`); err == nil {
		t.Fatal("non-string ciphertext accepted")
	}
}

func parameter(name, value string) []byte {
	result := append([]byte(name), 2)
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(value)))
	result = append(result, n[:]...)
	return append(result, []byte(value)...)
}

func TestGzipAndParameterParsing(t *testing.T) {
	p := testProfile(t)
	data := append(parameter("methodName", "execCommand"), parameter("cmdLine", "cmd /c tasklist /svc")...)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write(data)
	_ = writer.Close()
	d := decodeBody(encryptFixture(t, p, compressed.Bytes()), "/encrypted", []CryptoProfile{p})
	if d.Format != "binary-parameters" || !strings.Contains(d.Text, "tasklist") || len(d.Steps) != 5 {
		t.Fatalf("missing parameter reconstruction: %s", d.Message)
	}
	if _, err := unpackParameters([]byte{'x', 2, 255, 255, 255, 255}, 0); err == nil {
		t.Fatal("oversized parameter length accepted")
	}
	if _, err := unpackParameters(data, 13); err == nil {
		t.Fatal("recursive parsing limit missing")
	}
	var bomb bytes.Buffer
	zip := gzip.NewWriter(&bomb)
	_, _ = zip.Write(bytes.Repeat([]byte{'A'}, maxPlaintext+1))
	_ = zip.Close()
	result := Decoded{}
	if describePlain(bomb.Bytes(), &result) == nil {
		t.Fatal("gzip expansion cap missing")
	}
}

func TestHistoricalCiphertextHashes(t *testing.T) {
	root := os.Getenv("LOVELYLOG_PRIVATE_FIXTURE_DIR")
	if root == "" {
		t.Skip("private evidence is deliberately excluded; synthetic crypto fixtures run above")
	}
	if _, err := os.Stat(root); err != nil {
		t.Skip("private historical evidence not included in source distribution")
	}
	p := CryptoProfile{Name: "historical", PathRegex: `(?i)\.jsp`, Mode: "AES-CBC", SourceJSP: filepath.Join(root, "sample.txt"), PrefixBytes: 42, SuffixBytes: 45}
	if err := p.prepare(); err != nil {
		t.Fatal(err)
	}
	var manifest []struct {
		Frame     int `json:"frame"`
		BodyFiles []struct {
			File string `json:"file"`
		} `json:"body_files"`
	}
	var old struct {
		Records []struct {
			Frame     int    `json:"frame"`
			Direction string `json:"direction"`
			OK        bool   `json:"decryption_ok"`
			Decrypted struct {
				SHA256 string `json:"sha256"`
			} `json:"decrypted"`
		} `json:"records"`
	}
	read := func(name string, target any) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, target); err != nil {
			t.Fatal(err)
		}
	}
	read("http_bodies_manifest.json", &manifest)
	read(filepath.Join("decrypted", "decryption_results.json"), &old)
	byFrame := map[int]string{}
	for _, row := range manifest {
		if len(row.BodyFiles) > 0 {
			byFrame[row.Frame] = row.BodyFiles[0].File
		}
	}
	checked := 0
	for _, row := range old.Records {
		if !row.OK {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, byFrame[row.Frame]))
		if err != nil {
			t.Fatal(err)
		}
		profile := p
		if row.Direction == "response" {
			profile.PrefixBytes = 0
			profile.SuffixBytes = 0
			profile.Field = "data.repData.pointJson"
		}
		plain, err := profile.decrypt(string(body))
		if err != nil {
			t.Fatalf("frame %d: %v", row.Frame, err)
		}
		hash := sha256.Sum256(plain)
		if hex.EncodeToString(hash[:]) != row.Decrypted.SHA256 {
			t.Fatalf("frame %d plaintext differs from verified historical recovery", row.Frame)
		}
		if row.Direction == "request" {
			result := Decoded{}
			if err := describePlain(plain, &result); err != nil {
				t.Fatalf("frame %d cannot reconstruct request: %v", row.Frame, err)
			}
		}
		checked++
	}
	if checked < 7 {
		t.Fatalf("expected at least seven historical request/response checks, got %d", checked)
	}
	t.Logf("verified %d historical AES plaintext hashes without executing JSP/Class content", checked)
}
