package main

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const Version = "0.2.3"

type M map[string]any

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func obj(v any) M {
	if m, ok := v.(map[string]any); ok {
		return M(m)
	}
	if m, ok := v.(M); ok {
		return m
	}
	return M{}
}
func seq(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}
func strs(v any) []string {
	var out []string
	for _, x := range seq(v) {
		out = append(out, str(x))
	}
	return out
}
func yes(v any) bool { return v == true || str(v) == "true" }
func number(v any, fallback int) int {
	var n int
	if _, e := fmt.Sscan(str(v), &n); e != nil {
		return fallback
	}
	return n
}
func keys(m M) []string {
	a := make([]string, 0, len(m))
	for k := range m {
		a = append(a, k)
	}
	sortStrings(a)
	return a
}
func parseYAML(b []byte) (M, error) {
	var m M
	e := yaml.Unmarshal(b, &m)
	if m == nil && e == nil {
		e = fmt.Errorf("配置必须是 YAML 对象")
	}
	return m, e
}
func readJSON(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return atomicWrite(path, append(b, '\n'), 0600)
}
func atomicWrite(path string, b []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".write-*")
	if e != nil {
		return e
	}
	n := f.Name()
	defer os.Remove(n)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(n, path)
	}
	if e == nil {
		if dir, err := os.Open(filepath.Dir(path)); err == nil {
			e = dir.Sync()
			_ = dir.Close()
		}
	}
	return e
}

func linkOrCopy(source, dest string) error {
	if e := os.Link(source, dest); e == nil {
		return nil
	}
	b, e := os.ReadFile(source)
	if e != nil {
		return e
	}
	return atomicWrite(dest, b, 0600)
}

type Settings struct {
	Listen       string `json:"listen"`
	Dae          string `json:"dae"`
	Mihomo       string `json:"mihomo"`
	LAN          string `json:"lan"`
	WAN          string `json:"wan"`
	DNSBind      string `json:"dns_bind"`
	LogLevel     string `json:"log_level"`
	UpdateTime   string `json:"update_time"`
	Timezone     string `json:"timezone"`
	AutoUpdate   bool   `json:"auto_update"`
	RefreshRules bool   `json:"refresh_rules"`
	ApplyMode    string `json:"apply_mode"`
	Strict       bool   `json:"strict"`
	LogPath      string `json:"log_path"`
	TokenHash    string `json:"token_hash"`
}

func defaultSettings(root string) Settings {
	return Settings{Listen: "127.0.0.1:2025", Dae: "/usr/local/bin/dae", Mihomo: "/usr/local/lib/dae-manager/mihomo", LAN: "", WAN: "auto", DNSBind: "127.0.0.1:5353", LogLevel: "info", UpdateTime: "04:15", Timezone: "Asia/Shanghai", AutoUpdate: true, Strict: true, LogPath: "/tmp/dae-manager/dae.log"}
}
func (s Settings) validate() error {
	if !in(s.ApplyMode, []string{"", "restart", "reload"}) {
		return fmt.Errorf("配置应用方式必须为 restart 或 reload")
	}
	if _, e := time.LoadLocation(s.Timezone); e != nil {
		return fmt.Errorf("时区无效")
	}
	if _, e := time.Parse("15:04", s.UpdateTime); e != nil {
		return fmt.Errorf("更新时间必须为 HH:MM")
	}
	if !in(s.LogLevel, []string{"error", "warn", "info", "debug", "trace"}) {
		return fmt.Errorf("日志级别无效")
	}
	for _, v := range []string{s.LAN, s.WAN} {
		for _, iface := range strings.Split(v, ",") {
			if in(iface, []string{"dae0", "dae0peer"}) {
				return fmt.Errorf("%s 是 dae 内部接口保留名称，请更换物理网卡名称", iface)
			}
		}
		for _, r := range v {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.-,:@", r)) {
				return fmt.Errorf("网卡名称包含非法字符")
			}
		}
	}
	return validateBind(s.DNSBind)
}
func (s Settings) applyMode() string {
	if s.ApplyMode == "reload" {
		return "reload"
	}
	return "restart"
}
func in(x string, a []string) bool {
	for _, v := range a {
		if x == v {
			return true
		}
	}
	return false
}

type Node struct {
	Name        string `json:"name"`
	ID          string `json:"id"`
	Type        string `json:"type"`
	Provider    string `json:"provider"`
	URI         string `json:"-"`
	Fingerprint string `json:"fingerprint,omitempty"`
}
type Group struct {
	Name      string   `json:"name"`
	ID        string   `json:"id"`
	Type      string   `json:"type"`
	Choices   []string `json:"choices"`
	Selected  string   `json:"selected"`
	Members   []string `json:"members"`
	Policy    string   `json:"policy"`
	CheckURL  string   `json:"check_url"`
	Interval  int      `json:"interval"`
	Tolerance int      `json:"tolerance"`
}
type Rule struct {
	Source   string `json:"source"`
	Expr     string `json:"expression"`
	Target   string `json:"target"`
	Resolved string `json:"resolved"`
}
type Notice struct {
	Level   string `json:"level"`
	Feature string `json:"feature"`
	Detail  string `json:"detail"`
}
type ProviderInfo struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Count  int    `json:"count"`
	Digest string `json:"digest"`
}
type Report struct {
	Created    time.Time      `json:"created"`
	Nodes      []Node         `json:"nodes"`
	Groups     []Group        `json:"groups"`
	Rules      []Rule         `json:"rules"`
	Providers  []ProviderInfo `json:"providers"`
	Notices    []Notice       `json:"notices"`
	Validation string         `json:"validation"`
	ConfigHash string         `json:"config_hash"`
}

func (r *Report) note(level, feature, detail string) {
	r.Notices = append(r.Notices, Notice{level, feature, detail})
}
