package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

type FieldDecode struct {
	Path    string   `json:"path"`
	State   string   `json:"state"`
	Format  string   `json:"format,omitempty"`
	Profile string   `json:"profile,omitempty"`
	Steps   []string `json:"steps,omitempty"`
	Message string   `json:"message,omitempty"`
	SHA256  string   `json:"sha256,omitempty"`
	Bytes   int      `json:"bytes"`
	Source  string   `json:"source,omitempty"`
}

type bodyWalker struct {
	uri                                                         string
	profiles                                                    []CryptoProfile
	fields                                                      []FieldDecode
	nodes, processed, decrypted, restored, unresolved, failures int
	budget                                                      int
	limited                                                     bool
	root                                                        *Decoded
}

func jsonContainer(text string) (any, bool) {
	s := strings.TrimSpace(text)
	if !strings.HasPrefix(s, "{") && !strings.HasPrefix(s, "[") {
		return nil, false
	}
	var v any
	if json.Unmarshal([]byte(s), &v) != nil {
		return nil, false
	}
	return v, true
}

func (w *bodyWalker) unavailable(path, text, state, format, message string) any {
	hash := sha256.Sum256([]byte(text))
	w.unresolved++
	if state == "failed" {
		w.failures++
	}
	field := FieldDecode{Path: path, State: state, Format: format, Message: message, Bytes: len(text), SHA256: hex.EncodeToString(hash[:])}
	w.fields = append(w.fields, field)
	return map[string]any{"_unavailable": true, "state": state, "format": format, "reason": message, "bytes": len(text), "ciphertext_sha256": field.SHA256}
}

func (w *bodyWalker) walk(value any, path, field string, cipherHint bool, depth int) any {
	w.nodes++
	if depth > 20 || w.nodes > 20000 {
		w.limited = true
		return map[string]any{"_unavailable": true, "reason": "递归或字段数量超过解析限制"}
	}
	switch v := value.(type) {
	case map[string]any:
		hint := false
		if head, ok := v["head"].(map[string]any); ok {
			if marker, ok := head["encrypt_type"].(string); ok {
				hint = marker != "" && !strings.EqualFold(marker, "none")
			}
		}
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(v))
		for _, key := range keys {
			out[key] = w.walk(v[key], path+"."+key, key, hint && key == "body", depth+1)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = w.walk(child, fmt.Sprintf("%s[%d]", path, i), field, cipherHint, depth+1)
		}
		return out
	case string:
		if v == "" {
			return v
		}
		if nested, ok := jsonContainer(v); ok {
			w.processed++
			w.fields = append(w.fields, FieldDecode{Path: path, State: "decoded", Format: "json", Steps: []string{"展开 JSON 字符串"}, Bytes: len(v)})
			return w.walk(nested, path, field, false, depth+1)
		}
		// Only expand URL/Base64 layers when they produce a structured container.
		// This avoids interpreting IDs, ordinary strings and AES ciphertext as plaintext.
		if strings.Contains(v, "%") {
			if decoded, err := url.PathUnescape(v); err == nil && decoded != v && utf8.ValidString(decoded) {
				if _, ok := jsonContainer(decoded); ok || strings.HasPrefix(strings.ToLower(decoded), "%7b") || strings.HasPrefix(strings.ToLower(decoded), "%5b") {
					w.processed++
					w.fields = append(w.fields, FieldDecode{Path: path, State: "decoded", Format: "url", Steps: []string{"URL 百分号解码（保留 +）"}, Bytes: len(decoded)})
					return w.walk(decoded, path, field, cipherHint, depth+1)
				}
			}
		}
		target := path == "$" || field == "body" || field == "body_content"
		matching := []CryptoProfile{}
		for _, profile := range w.profiles {
			if profile.path != nil && profile.path.MatchString(w.uri) && ((profile.Field == "" && target) || "$"+"."+profile.Field == path) {
				if profile.Mode == "BACKEND-LOG" {
					hash := sha256.Sum256([]byte(v))
					if _, ok := profile.lookup[hex.EncodeToString(hash[:])]; !ok {
						continue
					}
				}
				matching = append(matching, profile)
			}
		}
		var lastError string
		for _, profile := range matching {
			copy := profile
			copy.Field = ""
			plain, err := copy.decrypt(v)
			if err == nil {
				steps := []string{"标准 Base64 解码", profile.Mode + " 解密", "严格 PKCS7 校验"}
				if profile.Mode == "RSA-AES-GCM" {
					steps = []string{"四段 Base64 解包", profile.RSAPadding + " 解封 AES 密钥", "AES-GCM 解密并验证认证标签"}
				}
				d := Decoded{State: "decrypted", Profile: profile.Name, Steps: steps}
				if err = describePlain(plain, &d); err == nil {
					w.budget -= d.Bytes
					if w.budget < 0 {
						w.limited = true
						return w.unavailable(path, v, "failed", "limit", "解码总量超过 8 MB 限制")
					}
					fieldResult := FieldDecode{Path: path, State: "decrypted", Format: d.Format, Profile: d.Profile, Steps: d.Steps, Bytes: d.Bytes, SHA256: d.SHA256}
					if profile.Mode == "BACKEND-LOG" {
						hash := sha256.Sum256([]byte(v))
						known := profile.lookup[hex.EncodeToString(hash[:])]
						d.State = "restored"
						d.Steps = []string{"密文 SHA-256 精确匹配", "读取同一后端请求的已解密报文", "明文 SHA-256 校验"}
						fieldResult.State = "restored"
						fieldResult.Steps = d.Steps
						fieldResult.Source = known.Source
						w.restored++
					} else {
						w.decrypted++
					}
					w.fields = append(w.fields, fieldResult)
					if path == "$" {
						w.root = &d
					}
					if nested, ok := jsonContainer(d.Text); ok {
						return w.walk(nested, path, field, false, depth+1)
					}
					return d.Text
				}
			}
			lastError = err.Error()
		}
		if _, ok := hybridParts(v); ok {
			state, message := "encrypted", "四段混合加密封装（疑似 RSA + AES-GCM）；需要匹配的业务私钥与封装参数。"
			if lastError != "" {
				state, message = "failed", lastError
			}
			return w.unavailable(path, v, state, "hybrid-envelope", message)
		}
		if target {
			for _, encoding := range []*base64.Encoding{base64.StdEncoding.Strict(), base64.RawStdEncoding.Strict(), base64.URLEncoding.Strict(), base64.RawURLEncoding.Strict()} {
				plain, err := encoding.DecodeString(v)
				if err != nil {
					continue
				}
				if utf8.Valid(plain) {
					if _, ok := jsonContainer(string(plain)); ok {
						w.processed++
						w.fields = append(w.fields, FieldDecode{Path: path, State: "decoded", Format: "base64-json", Steps: []string{"Base64 解码（非密码学解密）"}, Bytes: len(plain)})
						return w.walk(string(plain), path, field, false, depth+1)
					}
				}
				if cipherHint || (len(plain) >= 32 && len(plain)%16 == 0 && !utf8.Valid(plain)) {
					return w.unavailable(path, v, "encrypted", "aes-candidate", "Base64 密文；缺少匹配的业务密钥、模式或 IV。")
				}
			}
		}
		if lastError != "" {
			return w.unavailable(path, v, "failed", "", lastError)
		}
		if target && cipherHint {
			return w.unavailable(path, v, "encrypted", "unknown", "业务标记为加密，但格式尚未匹配；原始密文已保留。")
		}
		return v
	default:
		return value
	}
}

func decodeBody(body, uri string, profiles []CryptoProfile) Decoded {
	if body == "" || body == "-" {
		return Decoded{State: "empty", Text: "", Steps: []string{}, Message: "日志中没有正文：请求可能为空、被提前拦截或正文已落盘。"}
	}
	if len(body) > maxPlaintext {
		return Decoded{State: "failed", Message: "正文超过 8 MB 解析限制"}
	}
	w := bodyWalker{uri: uri, profiles: profiles, budget: maxPlaintext}
	value := w.walk(body, "$", "", false, 0)
	result := Decoded{State: "plain", Format: "text", Steps: []string{}, Fields: w.fields, Unresolved: w.unresolved}
	if w.root != nil {
		result = *w.root
		result.Fields = w.fields
		result.Unresolved = w.unresolved
	}
	if text, ok := value.(string); ok {
		result.Text = text
	} else {
		raw, _ := json.MarshalIndent(value, "", "  ")
		result.Text = string(raw)
		if w.root == nil || w.root.Format == "json" {
			result.Format = "json"
		}
	}
	if w.root == nil {
		h := sha256.Sum256([]byte(result.Text))
		result.SHA256 = hex.EncodeToString(h[:])
		result.Bytes = len(result.Text)
	}
	switch {
	case w.limited:
		result.State = "partial"
		result.Message = "部分内容超过解析限制，未完整还原。"
	case w.unresolved > 0 && (w.decrypted > 0 || w.restored > 0 || w.processed > 1):
		result.State = "partial"
	case w.unresolved > 0 && w.failures > 0:
		result.State = "failed"
	case w.unresolved > 0:
		result.State = "encrypted"
	case w.decrypted > 0:
		result.State = "decrypted"
	case w.restored > 0:
		result.State = "restored"
	case w.processed > 1:
		result.State = "decoded"
	}
	if w.unresolved > 0 {
		result.Message = fmt.Sprintf("已解密 %d 个字段、日志关联还原 %d 个字段；仍有 %d 个字段未还原。详情见字段处理记录，原始密文完整保留。", w.decrypted, w.restored, w.unresolved)
	}
	if result.State == "restored" {
		result.Message = "按相同密文精确关联后端已解密报文；这是历史明文还原，没有破解或猜测业务密钥。"
	}
	if result.State == "decoded" {
		result.Message = "已展开 JSON / 编码层；编码还原不等于密码学解密。"
	}
	return result
}
