package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Listen       string          `json:"listen"`
	LogPath      string          `json:"log_path"`
	DataFile     string          `json:"data_file"`
	EnvFile      string          `json:"livelog_env"`
	PanelURL     string          `json:"panel_url,omitempty"`
	PanelKey     string          `json:"panel_api_key,omitempty"`
	PanelPrefix  string          `json:"panel_api_prefix,omitempty"`
	PollSeconds  int             `json:"poll_seconds"`
	InitialLines int             `json:"initial_lines"`
	Profiles     []CryptoProfile `json:"crypto_profiles"`
	AI           AIConfig        `json:"ai"`
	AnalysisMode string          `json:"analysis_mode,omitempty"`
	Defense      DefenseConfig   `json:"defense"`
	KeyFiles     []string        `json:"key_files,omitempty"`
	keyInfo      []KeyFileInfo
	env          map[string]string
}

type AIConfig struct {
	BaseURL string `json:"base_url,omitempty"`
	Key     string `json:"api_key,omitempty"`
	Model   string `json:"model,omitempty"`
}

func resolvePath(base, name string) string {
	if name == "" || filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(base, name)
}

func readEnv(path string) (map[string]string, error) {
	result := map[string]string{}
	if path == "" {
		return result, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 Livelog 配置失败：%w", err)
	}
	for _, line := range strings.Split(strings.TrimPrefix(string(data), "\ufeff"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			result[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), "\"'")
		}
	}
	return result, nil
}

func loadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("配置不是有效 JSON：%w", err)
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return c, err
	}
	c.EnvFile = resolvePath(base, c.EnvFile)
	c.env, err = readEnv(c.EnvFile)
	if err != nil {
		return c, err
	}
	envMode := strings.ToLower(strings.TrimSpace(c.env["AI_ANALYSIS_MODE"]))
	if envMode != "" && envMode != "local" && envMode != "ai" {
		return c, errors.New("AI_ANALYSIS_MODE 仅支持 local 或 ai")
	}
	// A shared local-only setting must override an old per-app AI setting.
	if c.AnalysisMode == "" || envMode == "local" {
		c.AnalysisMode = envMode
	}
	c.AnalysisMode = strings.ToLower(strings.TrimSpace(c.AnalysisMode))
	if c.AnalysisMode == "" {
		c.AnalysisMode = "local"
	}
	if c.AnalysisMode != "local" && c.AnalysisMode != "ai" {
		return c, errors.New("analysis_mode / AI_ANALYSIS_MODE 仅支持 local 或 ai")
	}
	if c.PanelURL == "" {
		c.PanelURL = c.env["PANEL_URL"]
	}
	if c.PanelKey == "" {
		c.PanelKey = c.env["PANEL_API_KEY"]
	}
	if c.PanelPrefix == "" {
		c.PanelPrefix = c.env["PANEL_API_PREFIX"]
	}
	if c.PanelPrefix == "" {
		c.PanelPrefix = "/api/v2"
	}
	c.PanelURL = strings.TrimRight(c.PanelURL, "/")
	if err := validEndpoint(c.PanelURL); err != nil {
		return c, fmt.Errorf("1Panel 地址：%w", err)
	}
	if c.PanelKey == "" {
		return c, errors.New("缺少 1Panel API 密钥，请指定 livelog_env 或 panel_api_key")
	}
	if c.PanelPrefix != "/api/v1" && c.PanelPrefix != "/api/v2" {
		return c, errors.New("不支持的 1Panel API 前缀")
	}
	if c.LogPath == "" {
		c.LogPath = "/opt/1panel/www/sites/example-app/log/post.log"
	}
	if !strings.HasPrefix(c.LogPath, "/") || !strings.HasSuffix(c.LogPath, "/post.log") {
		return c, errors.New("log_path 必须是服务器上的绝对 post.log 路径")
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8790"
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return c, errors.New("查看界面仅支持监听本机回环地址，例如 127.0.0.1:8790")
	}
	if c.DataFile == "" {
		c.DataFile = "runtime/post.db"
	}
	c.DataFile = resolvePath(base, c.DataFile)
	if c.PollSeconds == 0 {
		c.PollSeconds = 3
	}
	if c.PollSeconds < 1 || c.PollSeconds > 300 {
		return c, errors.New("poll_seconds 必须为 1–300")
	}
	if c.InitialLines == 0 {
		c.InitialLines = 200
	}
	if c.InitialLines < 0 || c.InitialLines > 5000 {
		return c, errors.New("initial_lines 必须为 0–5000")
	}
	for i := range c.Profiles {
		c.Profiles[i].SourceJSP = resolvePath(base, c.Profiles[i].SourceJSP)
		c.Profiles[i].PrivateKeyFile = resolvePath(base, c.Profiles[i].PrivateKeyFile)
		c.Profiles[i].LookupFile = resolvePath(base, c.Profiles[i].LookupFile)
		if err = c.Profiles[i].prepare(); err != nil {
			return c, fmt.Errorf("解密配置 %q：%w", c.Profiles[i].Name, err)
		}
	}
	for _, name := range c.KeyFiles {
		c.keyInfo = append(c.keyInfo, inspectKeyFile(resolvePath(base, name)))
	}
	if c.AI.Key == "" {
		if c.env["AI_PROVIDER"] == "openai" {
			c.AI = AIConfig{c.env["OPENAI_BASE_URL"], c.env["OPENAI_API_KEY"], c.env["OPENAI_MODEL"]}
		} else {
			c.AI = AIConfig{c.env["DEEPSEEK_BASE_URL"], c.env["DEEPSEEK_API_KEY"], c.env["DEEPSEEK_MODEL"]}
			if c.AI.BaseURL == "" {
				c.AI.BaseURL = "https://api.deepseek.com"
			}
		}
	}
	if c.AnalysisMode != "local" && c.AI.Key != "" {
		if err := validEndpoint(c.AI.BaseURL); err != nil {
			return c, fmt.Errorf("AI 地址：%w", err)
		}
		if c.AI.Model == "" {
			return c, errors.New("AI 已配置密钥但缺少模型名称")
		}
	}
	if err := c.Defense.validate(); err != nil {
		return c, err
	}
	return c, nil
}

func validEndpoint(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("需要有效的 HTTP(S) 地址")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("需要有效的 HTTP(S) 地址")
	}
	return nil
}
