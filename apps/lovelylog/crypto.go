package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxPlaintext = 8 * 1024 * 1024

type CryptoProfile struct {
	Name           string `json:"name"`
	PathRegex      string `json:"path_regex"`
	Mode           string `json:"mode"`
	KeyBase64      string `json:"key_base64,omitempty"`
	IVBase64       string `json:"iv_base64,omitempty"`
	SourceJSP      string `json:"source_jsp,omitempty"`
	Field          string `json:"field,omitempty"`
	PrefixBytes    int    `json:"prefix_bytes"`
	SuffixBytes    int    `json:"suffix_bytes"`
	PrivateKeyFile string `json:"private_key_file,omitempty"`
	RSAPadding     string `json:"rsa_padding,omitempty"`
	LookupFile     string `json:"lookup_file,omitempty"`
	lookup         map[string]KnownPlaintext
	privateKey     *rsa.PrivateKey
	key, iv        []byte
	path           *regexp.Regexp
}

type Decoded struct {
	State      string        `json:"state"`
	Profile    string        `json:"profile,omitempty"`
	Format     string        `json:"format,omitempty"`
	Text       string        `json:"text"`
	SHA256     string        `json:"sha256,omitempty"`
	Bytes      int           `json:"bytes"`
	Steps      []string      `json:"steps,omitempty"`
	Message    string        `json:"message,omitempty"`
	Fields     []FieldDecode `json:"fields,omitempty"`
	Unresolved int           `json:"unresolved,omitempty"`
}

var javaUnicode = regexp.MustCompile(`\\u+([0-9a-fA-F]{4})`)
var keyLiteral = regexp.MustCompile(`SecretKeySpec\s*\(\s*base64Decode\s*\(\s*"([A-Za-z0-9+/=]+)"`)
var ivLiteral = regexp.MustCompile(`IvParameterSpec\s*\(\s*base64Decode\s*\(\s*"([A-Za-z0-9+/=]+)"`)

func (p *CryptoProfile) prepare() error {
	if p.Name == "" {
		return errors.New("缺少名称")
	}
	var err error
	if p.PathRegex == "" {
		return errors.New("必须指定 path_regex，避免将密钥用于不相关业务")
	}
	p.path, err = regexp.Compile(p.PathRegex)
	if err != nil {
		return errors.New("path_regex 无效")
	}
	if p.Mode == "" {
		p.Mode = "AES-CBC"
	}
	p.Mode = strings.ToUpper(p.Mode)
	if p.Mode == "BACKEND-LOG" {
		return p.prepareLookup()
	}
	if p.Mode == "RSA-AES-GCM" {
		return p.prepareHybrid()
	}
	if p.Mode != "AES-CBC" && p.Mode != "AES-ECB" {
		return errors.New("支持 AES-CBC / AES-ECB（PKCS7）及 RSA-AES-GCM")
	}
	if p.PrefixBytes < 0 || p.SuffixBytes < 0 || p.PrefixBytes > maxPlaintext || p.SuffixBytes > maxPlaintext {
		return errors.New("包装长度无效")
	}
	if p.SourceJSP != "" {
		data, err := os.ReadFile(p.SourceJSP)
		if err != nil {
			return errors.New("无法读取 source_jsp 文件")
		}
		if len(data) > 1024*1024 {
			return errors.New("JSP 样本超过 1 MB")
		}
		text := javaUnicode.ReplaceAllStringFunc(string(data), func(s string) string {
			n, _ := strconv.ParseUint(s[len(s)-4:], 16, 16)
			return string(rune(n))
		})
		key, iv := keyLiteral.FindStringSubmatch(text), ivLiteral.FindStringSubmatch(text)
		if len(key) != 2 || (p.Mode == "AES-CBC" && len(iv) != 2) {
			return errors.New("样本中没有已知形式的 AES Key / IV；仅做静态提取，不执行 JSP")
		}
		p.KeyBase64 = key[1]
		if len(iv) == 2 {
			p.IVBase64 = iv[1]
		}
	}
	p.key, err = base64.StdEncoding.Strict().DecodeString(p.KeyBase64)
	if err != nil || (len(p.key) != 16 && len(p.key) != 24 && len(p.key) != 32) {
		return errors.New("AES 密钥必须为 Base64 编码的 16 / 24 / 32 字节")
	}
	if p.Mode == "AES-CBC" {
		p.iv, err = base64.StdEncoding.Strict().DecodeString(p.IVBase64)
		if err != nil || len(p.iv) != aes.BlockSize {
			return errors.New("CBC IV 必须为 Base64 编码的 16 字节")
		}
	}
	return nil
}

func unpadPKCS7(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("密文长度不是 AES 块大小的整数倍")
	}
	n := int(data[len(data)-1])
	if n < 1 || n > blockSize || n > len(data) {
		return nil, errors.New("PKCS7 校验失败：密钥、IV 或包装不匹配")
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, errors.New("PKCS7 校验失败：密钥、IV 或包装不匹配")
		}
	}
	return data[:len(data)-n], nil
}

func (p CryptoProfile) decrypt(body string) ([]byte, error) {
	encoded := []byte(body)
	if p.Field != "" {
		var value any
		if err := json.Unmarshal(encoded, &value); err != nil {
			return nil, errors.New("正文不是有效 JSON，无法提取密文字段")
		}
		for _, name := range strings.Split(p.Field, ".") {
			object, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("密文字段路径不存在")
			}
			value, ok = object[name]
			if !ok {
				return nil, errors.New("密文字段路径不存在")
			}
		}
		text, ok := value.(string)
		if !ok {
			return nil, errors.New("指定字段不是密文字符串")
		}
		encoded = []byte(text)
	}
	if p.Mode == "RSA-AES-GCM" {
		return p.decryptHybrid(string(encoded))
	}
	if p.Mode == "BACKEND-LOG" {
		hash := sha256.Sum256(encoded)
		if known, ok := p.lookup[hex.EncodeToString(hash[:])]; ok {
			return []byte(known.Plaintext), nil
		}
		return nil, errors.New("历史明文索引无精确匹配")
	}
	if len(encoded) <= p.PrefixBytes+p.SuffixBytes {
		return nil, errors.New("正文短于配置的包装长度")
	}
	encoded = encoded[p.PrefixBytes : len(encoded)-p.SuffixBytes]
	encrypted, err := base64.StdEncoding.Strict().DecodeString(string(encoded))
	if err != nil {
		return nil, errors.New("密文不是有效的标准 Base64")
	}
	if len(encrypted) == 0 || len(encrypted)%aes.BlockSize != 0 {
		return nil, errors.New("密文长度不是 AES 块大小的整数倍")
	}
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return nil, errors.New("AES 密钥无效")
	}
	plain := make([]byte, len(encrypted))
	if p.Mode == "AES-CBC" {
		cipher.NewCBCDecrypter(block, p.iv).CryptBlocks(plain, encrypted)
	} else {
		for offset := 0; offset < len(encrypted); offset += aes.BlockSize {
			block.Decrypt(plain[offset:offset+aes.BlockSize], encrypted[offset:offset+aes.BlockSize])
		}
	}
	return unpadPKCS7(plain, aes.BlockSize)
}

func unpackParameters(data []byte, depth int) (map[string]any, error) {
	if depth > 12 {
		return nil, errors.New("嵌套参数超过限制")
	}
	result := map[string]any{}
	for len(data) > 0 {
		pos := bytes.IndexAny(data, "\x01\x02")
		if pos < 1 || pos > 100 || len(data) < pos+5 {
			return nil, errors.New("不是完整的二进制参数表")
		}
		name := string(data[:pos])
		if !regexp.MustCompile(`^[A-Za-z0-9_.$-]+$`).MatchString(name) {
			return nil, errors.New("二进制参数名无效")
		}
		if _, exists := result[name]; exists {
			return nil, errors.New("二进制参数名重复")
		}
		n := uint64(binary.LittleEndian.Uint32(data[pos+1 : pos+5]))
		if n > uint64(len(data)-(pos+5)) {
			return nil, errors.New("二进制参数长度超出正文")
		}
		value := data[pos+5 : pos+5+int(n)]
		if data[pos] == 1 {
			child, err := unpackParameters(value, depth+1)
			if err != nil {
				return nil, err
			}
			result[name] = child
		} else if utf8.Valid(value) && !bytes.ContainsRune(value, 0) {
			result[name] = string(value)
		} else {
			result[name] = map[string]any{"binary_base64": base64.StdEncoding.EncodeToString(value), "bytes": len(value)}
		}
		data = data[pos+5+int(n):]
	}
	if len(result) == 0 {
		return nil, errors.New("空参数表")
	}
	return result, nil
}

func describePlain(data []byte, result *Decoded) error {
	if bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return errors.New("gzip 头无效")
		}
		defer reader.Close()
		data, err = io.ReadAll(io.LimitReader(reader, maxPlaintext+1))
		if err != nil {
			return errors.New("gzip 解压或校验失败")
		}
		if len(data) > maxPlaintext {
			return errors.New("gzip 解压结果超过 8 MB 限制")
		}
		result.Steps = append(result.Steps, "gzip 解压并校验")
	}
	hash := sha256.Sum256(data)
	result.Bytes, result.SHA256 = len(data), hex.EncodeToString(hash[:])
	if bytes.HasPrefix(data, []byte{0xca, 0xfe, 0xba, 0xbe}) {
		result.Format = "java-class"
		stringsFound := regexp.MustCompile(`[\x20-\x7e]{5,}`).FindAll(data, 60)
		values := []string{}
		for _, item := range stringsFound {
			values = append(values, string(item[:min(len(item), 300)]))
		}
		value := map[string]any{"type": "Java Class（仅静态查看，不执行）", "bytes": len(data), "sha256": result.SHA256, "strings": values}
		if len(data) >= 8 {
			value["class_major"] = binary.BigEndian.Uint16(data[6:8])
		}
		text, _ := json.MarshalIndent(value, "", "  ")
		result.Text = string(text)
		return nil
	}
	if value, err := unpackParameters(data, 0); err == nil {
		text, _ := json.MarshalIndent(value, "", "  ")
		result.Format, result.Text = "binary-parameters", string(text)
		result.Steps = append(result.Steps, "解析长度标记的二进制参数（不执行内容）")
		return nil
	}
	if !utf8.Valid(data) || bytes.ContainsRune(data, 0) {
		return errors.New("填充通过，但输出不是支持的 UTF-8、gzip、参数表或 Java Class；未确认解密成功")
	}
	result.Format, result.Text = "text", string(data)
	if json.Valid(data) {
		var pretty bytes.Buffer
		_ = json.Indent(&pretty, data, "", "  ")
		result.Format, result.Text = "json", pretty.String()
	}
	return nil
}

func profileInfo(profiles []CryptoProfile) []map[string]string {
	result := []map[string]string{}
	for _, p := range profiles {
		if p.Mode == "BACKEND-LOG" {
			result = append(result, map[string]string{"name": p.Name, "mode": p.Mode, "path_regex": p.PathRegex, "lookup_entries": strconv.Itoa(len(p.lookup))})
			continue
		}
		material := p.key
		if p.privateKey != nil {
			material = p.privateKey.N.Bytes()
		}
		hash := sha256.Sum256(material)
		result = append(result, map[string]string{"name": p.Name, "mode": p.Mode, "path_regex": p.PathRegex, "key_fingerprint": fmt.Sprintf("%x", hash[:6])})
	}
	return result
}
