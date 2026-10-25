package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var webFiles embed.FS

type session struct{ Expires time.Time }
type attempt struct {
	Count int
	Since time.Time
}
type api struct {
	m        *Manager
	mu       sync.Mutex
	sessions map[string]session
	attempts map[string]attempt
}

func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func bad(w http.ResponseWriter, status int, e error) { respond(w, status, M{"error": e.Error()}) }
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		bad(w, 400, fmt.Errorf("请求内容无效或过大"))
		return false
	}
	if e := d.Decode(new(any)); e != io.EOF {
		bad(w, 400, fmt.Errorf("请求只能包含一个 JSON 对象"))
		return false
	}
	return true
}
func (a *api) authenticate(r *http.Request) bool {
	if token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); token != "" && a.m.authorized(token) {
		return true
	}
	cookie, e := r.Cookie("dae_session")
	if e != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[cookie.Value]
	return ok && time.Now().Before(s.Expires)
}
func originOK(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		u, e := url.Parse(origin)
		if e != nil || u.Host != r.Host {
			return false
		}
	}
	return true
}
func (a *api) handler() http.Handler {
	assets, _ := fs.Sub(webFiles, "web")
	static := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Method != "GET" && r.Method != "HEAD" {
				w.WriteHeader(405)
				return
			}
			static.ServeHTTP(w, r)
			return
		}
		if !originOK(r) {
			bad(w, 403, fmt.Errorf("跨站请求已拒绝"))
			return
		}
		if r.URL.Path == "/api/login" && r.Method == "POST" {
			a.login(w, r)
			return
		}
		if !a.authenticate(r) {
			bad(w, 401, fmt.Errorf("请先登录"))
			return
		}
		if r.Method != "GET" && r.Header.Get("X-DAE-Request") != "1" {
			bad(w, 403, fmt.Errorf("缺少请求保护标记"))
			return
		}
		a.route(w, r)
	})
}
func (a *api) login(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now()
	a.mu.Lock()
	v := a.attempts[ip]
	if now.Sub(v.Since) > 10*time.Minute {
		v = attempt{Since: now}
	}
	if v.Count >= 10 {
		a.mu.Unlock()
		bad(w, 429, fmt.Errorf("登录尝试过多，请十分钟后重试"))
		return
	}
	v.Count++
	if len(a.attempts) > 1024 {
		for k, x := range a.attempts {
			if now.Sub(x.Since) > 10*time.Minute {
				delete(a.attempts, k)
			}
		}
		if len(a.attempts) > 1024 {
			a.mu.Unlock()
			bad(w, 429, fmt.Errorf("登录请求过多"))
			return
		}
	}
	a.attempts[ip] = v
	a.mu.Unlock()
	var body struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !a.m.authorized(body.Token) {
		bad(w, 401, fmt.Errorf("管理口令错误"))
		return
	}
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		bad(w, 500, fmt.Errorf("无法创建会话"))
		return
	}
	token := hex.EncodeToString(b)
	a.mu.Lock()
	delete(a.attempts, ip)
	for k, s := range a.sessions {
		if now.After(s.Expires) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) > 100 {
		a.mu.Unlock()
		bad(w, 429, fmt.Errorf("会话数量已达上限"))
		return
	}
	a.sessions[token] = session{now.Add(12 * time.Hour)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "dae_session", Value: token, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	respond(w, 200, M{"ok": true})
}
func (a *api) job(w http.ResponseWriter, kind string, fn func(context.Context) error) {
	j, e := a.m.startJob(kind, fn)
	if e != nil {
		bad(w, 409, e)
		return
	}
	respond(w, 202, j)
}
func (a *api) route(w http.ResponseWriter, r *http.Request) {
	m := a.m
	path := r.URL.Path
	switch {
	case path == "/api/logout" && r.Method == "POST":
		if c, e := r.Cookie("dae_session"); e == nil {
			a.mu.Lock()
			delete(a.sessions, c.Value)
			a.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "dae_session", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		respond(w, 200, M{"ok": true})
	case path == "/api/status" && r.Method == "GET":
		s := m.settings()
		report, _ := m.liveReport(r.Context())
		var operations map[string]Job
		_ = readJSON(filepath.Join(m.Root, "operations.json"), &operations)
		sch := ScheduleState{}
		_ = readJSON(filepath.Join(m.Root, "schedule.json"), &sch)
		core := M{}
		_ = readJSON(filepath.Join(m.Root, "core-release.json"), &core)
		kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
		osr, _ := os.ReadFile("/etc/os-release")
		m.mu.RLock()
		j := m.job
		m.mu.RUnlock()
		respond(w, 200, M{"service": serviceState(r.Context()), "gateway": gateway(), "operations": operations, "version": Version, "process": m.coreProcess(), "revision": m.currentID(), "nodes": len(report.Nodes), "groups": len(report.Groups), "rules": len(report.Rules), "validation": report.Validation, "schedule": sch, "job": j, "core": core, "kernel": strings.TrimSpace(string(kernel)), "os": string(osr), "arch": runtime.GOARCH, "update_time": s.UpdateTime, "timezone": s.Timezone, "auto_update": s.AutoUpdate, "refresh_rules": s.RefreshRules, "dns_bind": s.DNSBind, "dae_dns_bind": dnsBackend(s.DNSBind), "lan": s.LAN, "wan": s.WAN, "log_level": s.LogLevel, "apply_mode": s.applyMode()})
	case path == "/api/report" && r.Method == "GET":
		report, e := m.liveReport(r.Context())
		if e != nil {
			bad(w, 404, fmt.Errorf("尚未应用配置"))
			return
		}
		respond(w, 200, struct {
			Report
			DisplayNames map[string]string `json:"display_names"`
		}{report, displayNames(report)})
	case path == "/api/job" && r.Method == "GET":
		m.mu.RLock()
		j := m.job
		m.mu.RUnlock()
		respond(w, 200, j)
	case path == "/api/doctor" && r.Method == "GET":
		respond(w, 200, doctor())
	case path == "/api/revisions" && r.Method == "GET":
		respond(w, 200, m.revisions())
	case path == "/api/logs" && r.Method == "GET":
		a.logs(w, r)
	case path == "/api/telemetry" && r.Method == "GET":
		respond(w, 200, m.telemetry(r.URL.Query().Get("sync") == "1"))
	case path == "/api/subscriptions" && r.Method == "GET":
		v, e := m.subscriptions()
		if e != nil {
			bad(w, 404, e)
			return
		}
		respond(w, 200, v)
	case path == "/api/subscriptions" && r.Method == "PUT":
		var body struct {
			Items      []SubscriptionLink `json:"items"`
			SourceHash string             `json:"source_hash"`
			Pull       bool               `json:"pull"`
			Rules      bool               `json:"rules"`
		}
		if !decode(w, r, &body) {
			return
		}
		kind := "subscription-save"
		if body.Pull {
			kind = "subscription-update"
		}
		a.job(w, kind, func(ctx context.Context) error {
			if e := m.saveSubscriptions(body.Items, body.SourceHash); e != nil {
				return e
			}
			if body.Pull {
				return m.update(ctx, body.Rules)
			}
			return nil
		})
	case path == "/api/update/result" && r.Method == "GET":
		result, e := m.lastSync()
		if e != nil {
			bad(w, 404, e)
			return
		}
		respond(w, 200, result)
	case path == "/api/nodes/test" && r.Method == "POST":
		var body struct {
			IDs []string `json:"ids"`
		}
		if !decode(w, r, &body) {
			return
		}
		a.job(w, "node-test", func(ctx context.Context) error { return m.manualProbe(ctx, body.IDs) })
	case path == "/api/dae/config" && r.Method == "GET":
		respond(w, 200, m.configView())
	case path == "/api/dae/config" && r.Method == "PUT":
		var body struct {
			Config       string `json:"config"`
			Apply        bool   `json:"apply"`
			BaseRevision string `json:"base_revision"`
		}
		if !decode(w, r, &body) {
			return
		}
		if len(body.Config) == 0 || len(body.Config) > 1<<20 {
			bad(w, 400, fmt.Errorf("配置必须介于 1 字节和 1 MiB"))
			return
		}
		a.job(w, "dae-config", func(ctx context.Context) error {
			if e := atomicWrite(filepath.Join(m.Root, "draft.dae"), []byte(body.Config), 0600); e != nil {
				return e
			}
			base := body.BaseRevision
			if base == "" {
				base = m.currentID()
			}
			if e := writeJSON(filepath.Join(m.Root, "draft-state.json"), M{"hash": digest([]byte(body.Config)), "base_revision": base}); e != nil {
				return e
			}
			if body.Apply {
				if base != m.currentID() {
					return fmt.Errorf("草稿基于旧版本；运行配置已变化，请先重新载入当前配置，再合并修改并应用")
				}
				return m.applyNative(ctx, []byte(body.Config))
			}
			return nil
		})
	case path == "/api/source" && r.Method == "GET":
		b, e := os.ReadFile(filepath.Join(m.Root, "source.yaml"))
		if e != nil {
			bad(w, 404, fmt.Errorf("尚无源配置"))
			return
		}
		respond(w, 200, M{"source": string(b)})
	case path == "/api/config" && r.Method == "GET":
		b, e := os.ReadFile(filepath.Join(m.currentDir(), "config.dae"))
		if e != nil {
			bad(w, 404, fmt.Errorf("尚无生效配置"))
			return
		}
		respond(w, 200, M{"config": string(b)})
	case path == "/api/source" && r.Method == "PUT":
		var body struct {
			Source string `json:"source"`
		}
		if !decode(w, r, &body) {
			return
		}
		if _, e := parseYAML([]byte(body.Source)); e != nil {
			bad(w, 400, fmt.Errorf("YAML 格式错误"))
			return
		}
		a.job(w, "import", func(ctx context.Context) error {
			id, _, e := m.build(ctx, true, true, []byte(body.Source), map[string]string{}, m.settings())
			if e != nil {
				return e
			}
			return m.activate(ctx, id, false)
		})
	case path == "/api/update" && r.Method == "POST":
		var body struct {
			Rules bool `json:"rules"`
		}
		if !decode(w, r, &body) {
			return
		}
		kind := "update"
		if body.Rules {
			kind = "update:rules"
		}
		a.job(w, kind, func(ctx context.Context) error { return m.update(ctx, body.Rules) })
	case path == "/api/validate" && r.Method == "POST":
		a.job(w, "validate", func(ctx context.Context) error { return m.validate(ctx, m.currentDir()) })
	case path == "/api/select" && r.Method == "POST":
		var body struct {
			Group  string `json:"group"`
			Choice string `json:"choice"`
		}
		if !decode(w, r, &body) {
			return
		}
		a.job(w, "select", func(ctx context.Context) error {
			report, e := m.report()
			if e != nil {
				return e
			}
			found := false
			for _, g := range report.Groups {
				if g.Name == body.Group && g.Type == "select" && in(body.Choice, g.Choices) {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("分组或选项无效")
			}
			selections := map[string]string{}
			if e = readJSON(filepath.Join(m.Root, "selections.json"), &selections); e != nil {
				return e
			}
			selections[body.Group] = body.Choice
			id, _, e := m.build(ctx, false, false, nil, selections, m.settings())
			if e != nil {
				return e
			}
			return m.activate(ctx, id, false)
		})
	case path == "/api/service" && r.Method == "POST":
		var body struct {
			Action string `json:"action"`
		}
		if !decode(w, r, &body) {
			return
		}
		a.job(w, "service:"+body.Action, func(ctx context.Context) error { return m.service(ctx, body.Action) })
	case path == "/api/rollback" && r.Method == "POST":
		var body struct {
			Revision string `json:"revision"`
		}
		if !decode(w, r, &body) {
			return
		}
		a.job(w, "rollback", func(ctx context.Context) error { return m.activate(ctx, body.Revision, false) })
	case path == "/api/settings" && r.Method == "PUT":
		var body struct {
			LAN          string  `json:"lan"`
			WAN          string  `json:"wan"`
			LogLevel     string  `json:"log_level"`
			UpdateTime   string  `json:"update_time"`
			Timezone     string  `json:"timezone"`
			AutoUpdate   bool    `json:"auto_update"`
			RefreshRules bool    `json:"refresh_rules"`
			ApplyMode    *string `json:"apply_mode"`
		}
		if !decode(w, r, &body) {
			return
		}
		s := m.settings()
		s.LAN = body.LAN
		s.WAN = body.WAN
		s.LogLevel = body.LogLevel
		s.UpdateTime = body.UpdateTime
		s.Timezone = body.Timezone
		s.AutoUpdate = body.AutoUpdate
		s.RefreshRules = body.RefreshRules
		if body.ApplyMode != nil {
			s.ApplyMode = *body.ApplyMode
		}
		if e := s.validate(); e != nil {
			bad(w, 400, e)
			return
		}
		a.job(w, "settings", func(ctx context.Context) error {
			// Enabling rule synchronization performs the first fetch now, before
			// committing the setting or applying the new revision.
			refresh := s.RefreshRules && !m.settings().RefreshRules
			id, _, e := m.build(ctx, false, refresh, nil, nil, s)
			if e != nil {
				return e
			}
			return m.activate(ctx, id, false)
		})
	default:
		bad(w, 404, fmt.Errorf("接口不存在或请求方法不支持"))
	}
}

type LogLine struct {
	Text     string `json:"text"`
	Category string `json:"category"`
	Level    string `json:"level"`
}

func logCategory(s string) string {
	s = strings.ToLower(s)
	if containsAny(s, []string{"dns", "qname", "qtype", "rcode", "resolver"}) {
		return "dns"
	}
	if containsAny(s, []string{"routing", "outbound", "dialer", "sniff", "tcp", "udp", "direct"}) {
		return "routing"
	}
	return "system"
}
func containsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}
func tail(path string, maxBytes int64) string {
	f, e := os.Open(path)
	if e != nil {
		return ""
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return ""
	}
	skip := st.Size() > maxBytes
	if skip {
		_, _ = f.Seek(-maxBytes, io.SeekEnd)
	}
	b, _ := io.ReadAll(io.LimitReader(f, maxBytes))
	s := string(b)
	if skip {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
	}
	return s
}
func filterLogs(text, q, category, level string, limit int) []LogLine {
	lines := strings.Split(text, "\n")
	out := []LogLine{}
	words := strings.Fields(strings.ToLower(q))
	for i := len(lines) - 1; i >= 0 && len(out) < limit; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		kind := logCategory(line)
		if category != "" && category != "all" && category != kind {
			continue
		}
		lv := "info"
		for _, v := range []string{"trace", "debug", "warn", "error", "fatal"} {
			if strings.Contains(lower, v) {
				lv = v
				break
			}
		}
		if level != "" && level != "all" && level != lv {
			continue
		}
		ok := true
		for _, word := range words {
			if !strings.Contains(lower, word) {
				ok = false
			}
		}
		if ok {
			out = append(out, LogLine{line, kind, lv})
		}
	}
	return out
}
func (a *api) logs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	limit = min(limit, 1000)
	path := a.m.settings().LogPath
	if q.Get("source") == "audit" {
		path = filepath.Join(a.m.Root, "audit.log")
	}
	text := rotatedLogs(path)
	if q.Get("source") != "audit" {
		text += "\n" + tail(filepath.Join(a.m.Root, "dns.log.1"), 5<<20) + "\n" + tail(filepath.Join(a.m.Root, "dns.log"), 5<<20)
		index := a.m.netflixIndex()
		lines := strings.Split(text, "\n")
		for i, line := range lines {
			lines[i] = enrichNetflix(line, index)
		}
		text = strings.Join(lines, "\n")
		lines = strings.Split(text, "\n")
		sort.SliceStable(lines, func(i, j int) bool { return logTime(lines[i]).Before(logTime(lines[j])) })
		text = strings.Join(lines, "\n")
	}
	if report, e := a.m.report(); e == nil {
		var pairs []string
		for _, n := range report.Nodes {
			pairs = append(pairs, n.ID, n.Name+" ["+n.ID+"]", id("solo_", n.Name), n.Name+" ["+id("solo_", n.Name)+"]")
		}
		for _, g := range report.Groups {
			pairs = append(pairs, g.ID, g.Name+" ["+g.ID+"]")
		}
		if len(pairs) > 0 {
			text = strings.NewReplacer(pairs...).Replace(text)
		}
	}
	out := filterLogs(text, q.Get("q"), q.Get("category"), q.Get("level"), limit)
	respond(w, 200, M{"lines": out, "limit": limit, "searched_bytes": len(text), "note": "检索核心最近三个轮转文件及 DNS 前置记录，较新记录在前；Netflix 支持域名别名及 IP 规则推断。旧 info 日志未记录的连接无法补回；加密 DNS、绕过此网关的流量不可见。DNS client 为转发方时不代表手机地址。"})
}
func (m *Manager) serve(ctx context.Context, withoutDNS bool) error {
	if m.settings().TokenHash == "" {
		return fmt.Errorf("请先执行 init")
	}
	unlock, e := m.lock()
	if e != nil {
		return e
	}
	e = m.recoverTransaction(ctx)
	unlock()
	if e != nil {
		return e
	}
	if !withoutDNS {
		if e = m.serveDNS(ctx); e != nil {
			return e
		}
	}
	go m.scheduler(ctx)
	a := &api{m: m, sessions: map[string]session{}, attempts: map[string]attempt{}}
	srv := &http.Server{Addr: m.settings().Listen, Handler: a.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	m.audit("manager_started", m.settings().Listen)
	e = srv.ListenAndServe()
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
