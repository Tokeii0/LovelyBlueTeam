package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
)

type KeyFileInfo struct {
	Name         string `json:"name"`
	Bytes        int    `json:"bytes"`
	DecodedBytes int    `json:"decoded_bytes,omitempty"`
	Format       string `json:"format"`
	Message      string `json:"message"`
}

func inspectKeyFile(path string) KeyFileInfo {
	info := KeyFileInfo{Name: filepath.Base(path), Format: "unrecognized"}
	raw, err := os.ReadFile(path)
	if err != nil {
		info.Message = "无法读取密钥文件"
		return info
	}
	info.Bytes = len(raw)
	if len(raw) > 65536 {
		info.Message = "文件超过 64 KB 检查限制"
		return info
	}
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	} else if data, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw))); err == nil {
		raw = data
		info.DecodedBytes = len(data)
	}
	key, err := x509.ParsePKCS1PrivateKey(raw)
	if err != nil {
		if parsed, e := x509.ParsePKCS8PrivateKey(raw); e == nil {
			key, _ = parsed.(*rsa.PrivateKey)
		}
	}
	if key != nil && key.Validate() == nil {
		info.Format = "rsa-private-key"
		info.Message = "已识别 RSA 私钥，可配置 RSA-AES-GCM 规则后核验业务密文。"
		return info
	}
	info.Message = "非标准 PKCS1 / PKCS8 RSA 私钥。已保留文件；若为业务系统加密保存的密钥，需要其加载算法或解封密钥。"
	return info
}
