package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const localRulesVersion = "local-regex-v1"
const localScanLimit = 128 * 1024

// These rules identify review candidates, not successful exploitation. XSS is
// deliberately excluded because payment XML caused false positives previously.
var findingRules = []struct {
	id, category, description string
	expression                *regexp.Regexp
}{
	{"SQL-001", "sql_injection", "UNION SELECT 注入语法", regexp.MustCompile(`(?is)\bunion(?:\s|/\*[^*]{0,128}\*/)+(?:all(?:\s|/\*[^*]{0,128}\*/)+)?select\b`)},
	{"SQL-002", "sql_injection", "SQL 延时或报错函数调用", regexp.MustCompile(`(?is)\b(?:sleep|pg_sleep|benchmark)\s*\(\s*[0-9]|\b(?:extractvalue|updatexml)\s*\(|\bwaitfor\s+delay\s*['"]`)},
	{"SQL-003", "sql_injection", "引号闭合后的 SQL 条件与注释组合", regexp.MustCompile(`(?is)['"]\s*(?:or|and)\s+(?:[0-9]{1,8}\s*=\s*[0-9]{1,8}|['"][^'"\r\n]{1,40}['"]\s*=\s*['"][^'"\r\n]{1,40}['"])\s*(?:--|#|/\*|['"])`)},
	{"RCE-001", "command", "命令解释器或 Java 进程执行调用", regexp.MustCompile(`(?i)\bcmd(?:\.exe)?\s*/[cq]\b|\bpowershell(?:\.exe)?\s+-(?:e(?:nc(?:odedcommand)?)?|command|c|nop(?:rofile)?)\b|/bin/(?:sh|bash)\s+-[ci]\b|Runtime\s*\.\s*getRuntime\s*\(\s*\)|\bProcessBuilder\s*\(`)},
	{"RCE-002", "command", "后门命令执行参数", regexp.MustCompile(`(?i)"method(?:Name)?"\s*:\s*"execCommand"`)},
	{"PATH-001", "path_traversal", "连续上级目录穿越", regexp.MustCompile(`(?:\.\.[/\\;]+){2,}`)},
	{"JNDI-001", "jndi", "JNDI 外联表达式", regexp.MustCompile(`(?i)\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|http|https)\s*:`)},
	{"JSP-001", "jsp_source", "JSP 脚本或动态类加载代码", regexp.MustCompile(`(?i)<%[@!=]?|\bdefineClass\s*\(`)},
	{"PHP-001", "php_source", "PHP 脚本或常见执行载荷", regexp.MustCompile(`(?is)<\?(?:php\b|=)|\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(|\b(?:system|shell_exec|passthru)\s*\(\s*\$_(?:GET|POST|REQUEST)\b`)},
	{"FILE-001", "sensitive_file", "敏感配置或版本库文件访问", regexp.MustCompile(`(?i)(?:^|[/\\])(?:\.env(?:\.[a-z0-9_-]+)?|\.git[/\\](?:HEAD|config)|wp-config\.php|WEB-INF[/\\]web\.xml)(?:$|[?&#"'\s/\\])|[/\\]actuator[/\\](?:env|heapdump)(?:$|[?&#"'\s])|[/\\]etc[/\\](?:passwd|shadow)\b|[/\\]windows[/\\]win\.ini\b`)},
}

var localJSONEscape = regexp.MustCompile(`\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[/\\"'nrtbf])`)
var localJNDILetter = regexp.MustCompile(`\$\{(?:(?:lower|upper):|::-)([A-Za-z])\}`)
var localPercentByte = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
var localTrackCode = regexp.MustCompile(`"sys_track_code"\s*:\s*"([^"\\\r\n]*)"|(?:^|[?&\s])sys_track_code=([^&\s"']+)`)
var validLocalTrackCode = regexp.MustCompile(`^YQ_[0-9]{16}_[0-9]{2}$`)

func normalizeLocalText(text string) string {
	if strings.ContainsAny(text, "%+") {
		if decoded, err := url.QueryUnescape(text); err == nil {
			text = decoded
		} else {
			// A literal malformed % elsewhere must not hide valid encoded bytes.
			text = localPercentByte.ReplaceAllStringFunc(text, func(value string) string {
				n, _ := strconv.ParseUint(value[1:], 16, 8)
				return string([]byte{byte(n)})
			})
			text = strings.ReplaceAll(text, "+", " ")
		}
	}
	if strings.Contains(text, `\`) {
		text = localJSONEscape.ReplaceAllStringFunc(text, func(value string) string {
			if value == `\'` {
				return "'"
			}
			if decoded, err := strconv.Unquote(`"` + value + `"`); err == nil {
				return decoded
			}
			return value
		})
	}
	return localJNDILetter.ReplaceAllString(text, "$1")
}

func localFindings(entry Entry) []Finding {
	result := []Finding{}
	seen := map[string]bool{}
	parts := []struct{ name, text string }{{"URI", entry.URI}, {"还原正文", entry.Decoded.Text}}
	if entry.Body != entry.Decoded.Text {
		parts = append(parts, struct{ name, text string }{"原始正文", entry.Body})
	}
	for _, part := range parts {
		text := part.text
		if len(text) > localScanLimit {
			text = text[:localScanLimit]
		}
		for round := 0; round <= 4 && text != ""; round++ {
			source := part.name
			if round > 0 {
				source += fmt.Sprintf("，规范化第 %d 轮", round)
			}
			for _, rule := range findingRules {
				if !seen[rule.id] {
					if hit := rule.expression.FindString(text); hit != "" {
						seen[rule.id] = true
						result = append(result, Finding{Category: rule.category, Description: rule.description, Evidence: runePrefix(redactText(hit), 180), Rule: rule.id, Source: source})
					}
				}
			}
			if !seen["YQ-001"] {
				for _, match := range localTrackCode.FindAllStringSubmatch(text, 16) {
					value := match[1]
					if value == "" {
						value = match[2]
					}
					if strings.HasPrefix(value, "YQ_") && !validLocalTrackCode.MatchString(value) {
						seen["YQ-001"] = true
						result = append(result, Finding{Category: "invalid_yq_track_code", Description: "YQ_ 开头的流水号不符合 YQ_16位数字_2位数字，仅作异常线索", Evidence: runePrefix(value, 180), Rule: "YQ-001", Source: source})
						break
					}
				}
			}
			next := normalizeLocalText(text)
			if next == text {
				break
			}
			text = next
		}
	}
	if entry.Decoded.Format == "java-class" {
		result = append(result, Finding{Category: "java_class", Description: "正文中还原出 Java Class；仅静态识别，未执行", Evidence: entry.Decoded.SHA256, Rule: "CLASS-001", Source: "还原正文"})
	}
	return result
}

func localReview(entries []Entry) string {
	var report strings.Builder
	fmt.Fprintf(&report, "LovelyLog 本地规则复核\n规则版本：%s\n本报告仅针对 LovelyLog 来源。本次未调用外部 AI，不自动封禁。请结合业务人工判断是否封禁。\n", localRulesVersion)
	for _, entry := range entries {
		fmt.Fprintf(&report, "\n记录 %d · %s · %s %s · HTTP %d\n", entry.ID, entry.IP, entry.Method, redactURI(entry.URI), entry.Status)
		findings := localFindings(entry)
		if len(findings) == 0 {
			report.WriteString("未命中当前本地规则。无命中不代表安全。\n")
		}
		for _, finding := range findings {
			fmt.Fprintf(&report, "- %s · %s：%s\n  来源：%s\n  证据：%s\n", finding.Rule, finding.Category, finding.Description, finding.Source, finding.Evidence)
		}
		switch entry.Decoded.State {
		case "encrypted", "failed", "empty", "partial":
			fmt.Fprintf(&report, "限制：正文状态为 %s，不能完整检查未解密或缺失的内容。\n", entry.Decoded.State)
		}
		if entry.Decoded.Unresolved > 0 {
			fmt.Fprintf(&report, "限制：仍有 %d 个字段未完整还原。\n", entry.Decoded.Unresolved)
		}
		if len(entry.URI) > localScanLimit || len(entry.Body) > localScanLimit || len(entry.Decoded.Text) > localScanLimit {
			report.WriteString("限制：长字段仅检查前 128 KiB，后续内容未经本次规则扫描。\n")
		}
	}
	report.WriteString("\n仅对 URI、原始正文和已有还原正文做有限静态匹配，最多还原四轮 URL 编码和常见 JSON 转义。规则命中不能证明攻击成功，HTTP 200 也不能证明命令已执行。XSS 规则当前不启用。")
	return report.String()
}
