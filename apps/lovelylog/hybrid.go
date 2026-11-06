package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"strings"
)

// This format is explicitly configured. A four-part shape alone is not proof of an algorithm.
func hybridParts(text string) ([][]byte, bool) {
	parts := strings.Split(text, ".")
	if len(parts) != 4 {
		return nil, false
	}
	result := make([][]byte, 4)
	for i, part := range parts {
		var err error
		result[i], err = base64.StdEncoding.Strict().DecodeString(part)
		if err != nil {
			return nil, false
		}
	}
	return result, (len(result[0]) == 256 || len(result[0]) == 384 || len(result[0]) == 512) && len(result[1]) == 12 && len(result[2]) == 16
}

func (p *CryptoProfile) prepareHybrid() error {
	if p.PrivateKeyFile == "" {
		return errors.New("RSA-AES-GCM 需要 private_key_file")
	}
	raw, err := os.ReadFile(p.PrivateKeyFile)
	if err != nil {
		return errors.New("无法读取业务 RSA 私钥文件")
	}
	if len(raw) > 65536 {
		return errors.New("业务私钥文件超过 64 KB")
	}
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	} else if decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw))); err == nil {
		raw = decoded
	}
	key, err := x509.ParsePKCS1PrivateKey(raw)
	if err != nil {
		parsed, parseErr := x509.ParsePKCS8PrivateKey(raw)
		if parseErr != nil {
			return errors.New("不是可读取的 PKCS1 / PKCS8 RSA 私钥；加密保存的业务文件需要对应加载方式")
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return errors.New("文件中的私钥不是 RSA")
		}
	}
	if key.N.BitLen() < 2048 || key.N.BitLen() > 4096 {
		return errors.New("RSA 私钥位数应为 2048–4096")
	}
	if err := key.Validate(); err != nil {
		return errors.New("RSA 私钥校验失败")
	}
	p.privateKey = key
	p.RSAPadding = strings.ToUpper(p.RSAPadding)
	if p.RSAPadding == "" {
		p.RSAPadding = "OAEP-SHA256"
	}
	if p.RSAPadding != "OAEP-SHA256" && p.RSAPadding != "OAEP-SHA1" && p.RSAPadding != "PKCS1V15" {
		return errors.New("rsa_padding 支持 OAEP-SHA256、OAEP-SHA1、PKCS1v15")
	}
	return nil
}

func (p CryptoProfile) decryptHybrid(text string) ([]byte, error) {
	parts, ok := hybridParts(text)
	if !ok || p.privateKey == nil || len(parts[0]) != p.privateKey.Size() {
		return nil, errors.New("四段密文格式或 RSA 密钥长度不匹配")
	}
	var key []byte
	var err error
	switch p.RSAPadding {
	case "PKCS1V15":
		key, err = rsa.DecryptPKCS1v15(rand.Reader, p.privateKey, parts[0])
	case "OAEP-SHA1":
		key, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, p.privateKey, parts[0], nil)
	default:
		key, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, p.privateKey, parts[0], nil)
	}
	if err != nil {
		return nil, errors.New("RSA 解封密钥失败；业务私钥或填充方式不匹配")
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("RSA 解封结果不是有效 AES 密钥")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("AES 密钥无效")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("无法初始化 GCM")
	}
	// Wire order: wrapped key, nonce, tag, ciphertext. Go expects ciphertext || tag.
	ciphertext := append(append([]byte{}, parts[3]...), parts[2]...)
	plain, err := gcm.Open(nil, parts[1], ciphertext, nil)
	if err != nil {
		return nil, errors.New("GCM 认证失败；密钥、标签、AAD 或封装方式不匹配，未输出猜测明文")
	}
	return plain, nil
}
