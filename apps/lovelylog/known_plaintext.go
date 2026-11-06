package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"unicode/utf8"
)

type KnownPlaintext struct {
	Plaintext       string `json:"plaintext"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
	Source          string `json:"source"`
}

func (p *CryptoProfile) prepareLookup() error {
	file, err := os.Open(p.LookupFile)
	if err != nil {
		return errors.New("无法读取后端明文索引")
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || stat.Size() > 32*1024*1024 {
		return errors.New("后端明文索引超过 32 MB 限制或无法读取")
	}
	if err = json.NewDecoder(file).Decode(&p.lookup); err != nil {
		return errors.New("后端明文索引不是有效 JSON")
	}
	valid := regexp.MustCompile(`^[a-f0-9]{64}$`)
	for key, item := range p.lookup {
		hash := sha256.Sum256([]byte(item.Plaintext))
		if !valid.MatchString(key) || !utf8.ValidString(item.Plaintext) || len(item.Plaintext) > maxPlaintext || item.Source == "" || hex.EncodeToString(hash[:]) != item.PlaintextSHA256 {
			return errors.New("后端明文索引缺少来源或明文哈希不匹配")
		}
	}
	return nil
}
