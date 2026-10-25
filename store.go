package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Manager struct {
	Root          string
	mu            sync.RWMutex
	op            sync.Mutex
	S             Settings
	job           Job
	processProbe  func() Process // injectable process boundary for transaction tests
	reloadAction  func(context.Context) error
	teleMu        sync.Mutex
	tele          Telemetry
	invMu         sync.Mutex
	inv           Inventory
	invRevision   string
	aliasMu       sync.Mutex
	netflix       NetflixIndex
	logMu         sync.Mutex
	buildObserver func(string, string, Report)
	syncResult    *SyncResult
}
type Job struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	State    string    `json:"state"`
	Message  string    `json:"message"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
}
type Revision struct {
	ID         string    `json:"id"`
	Created    time.Time `json:"created"`
	Nodes      int       `json:"nodes"`
	Active     bool      `json:"active"`
	Validation string    `json:"validation"`
}

func openManager(root string) (*Manager, error) {
	abs, e := filepath.Abs(root)
	if e != nil {
		return nil, e
	}
	m := &Manager{Root: abs, S: defaultSettings(abs)}
	e = readJSON(filepath.Join(abs, "settings.json"), &m.S)
	if os.IsNotExist(e) {
		return m, nil
	}
	return m, e
}
func (m *Manager) settings() Settings { m.mu.RLock(); defer m.mu.RUnlock(); return m.S }
func (m *Manager) init(source string, s Settings) (string, error) {
	if _, e := os.Stat(filepath.Join(m.Root, "settings.json")); e == nil {
		return "", fmt.Errorf("已初始化；拒绝覆盖现有配置")
	}
	if e := s.validate(); e != nil {
		return "", e
	}
	if e := os.MkdirAll(m.Root, 0700); e != nil {
		return "", e
	}
	_ = os.Chmod(m.Root, 0700)
	token := make([]byte, 32)
	if _, e := rand.Read(token); e != nil {
		return "", e
	}
	plain := hex.EncodeToString(token)
	s.TokenHash = digest([]byte(plain))
	m.S = s
	if source != "" {
		b, e := os.ReadFile(source)
		if e != nil {
			return "", e
		}
		if _, e = parseYAML(b); e != nil {
			return "", e
		}
		if e = atomicWrite(filepath.Join(m.Root, "source.yaml"), b, 0600); e != nil {
			return "", e
		}
	}
	if e := writeJSON(filepath.Join(m.Root, "settings.json"), s); e != nil {
		return "", e
	}
	if e := writeJSON(filepath.Join(m.Root, "selections.json"), map[string]string{}); e != nil {
		return "", e
	}
	if e := atomicWrite(filepath.Join(m.Root, "admin-token"), []byte(plain+"\n"), 0600); e != nil {
		return "", e
	}
	return plain, nil
}
func (m *Manager) authorized(token string) bool {
	s := m.settings()
	if s.TokenHash == "" {
		return false
	}
	got := digest([]byte(token))
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.TokenHash)) == 1
}
func (m *Manager) lock() (func(), error) {
	if !m.op.TryLock() {
		return nil, fmt.Errorf("另一个配置操作正在进行")
	}
	f, e := os.OpenFile(filepath.Join(m.Root, "operation.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		m.op.Unlock()
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		m.op.Unlock()
		return nil, fmt.Errorf("另一个管理进程正在更新")
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close(); m.op.Unlock() }, nil
}
func (m *Manager) currentID() string {
	s, e := os.Readlink(filepath.Join(m.Root, "current"))
	if e != nil {
		return ""
	}
	return filepath.Base(s)
}
func validRevision(s string) bool {
	return len(s) > 10 && !strings.ContainsAny(s, "/\\.") && strings.Trim(s, "0123456789-abcdef") == ""
}
func (m *Manager) currentDir() string {
	id := m.currentID()
	if !validRevision(id) {
		return filepath.Join(m.Root, "uninitialized")
	}
	return filepath.Join(m.Root, "revisions", id)
}
func (m *Manager) report() (Report, error) {
	var r Report
	e := readJSON(filepath.Join(m.currentDir(), "report.json"), &r)
	return r, e
}
func (m *Manager) audit(event, message string) {
	path := filepath.Join(m.Root, "audit.log")
	if info, e := os.Stat(path); e == nil && info.Size() > 2<<20 {
		_ = os.Rename(path, path+".1")
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e == nil {
		defer f.Close()
		b, _ := json.Marshal(map[string]any{"time": time.Now().Format(time.RFC3339), "event": event, "message": message})
		_, _ = f.Write(append(b, '\n'))
	}
}
func (m *Manager) validate(ctx context.Context, path string) error {
	s := m.settings()
	tc, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(tc, s.Dae, "validate", "-c", filepath.Join(path, "config.dae"))
	cmd.Dir = path
	out, e := cmd.CombinedOutput()
	if e != nil {
		_ = atomicWrite(filepath.Join(path, "validation-error.txt"), out, 0600)
		return fmt.Errorf("dae 原生校验失败；诊断已保存在该版本的 validation-error.txt（可能含节点信息，不通过公开日志输出）")
	}
	return nil
}
func (m *Manager) build(ctx context.Context, refreshNodes, refreshRules bool, source []byte, selections map[string]string, s Settings) (string, Report, error) {
	if len(source) == 0 {
		var e error
		source, e = os.ReadFile(filepath.Join(m.Root, "source.yaml"))
		if e != nil {
			return "", Report{}, fmt.Errorf("请先导入 Mihomo 配置")
		}
	}
	if selections == nil {
		selections = map[string]string{}
		_ = readJSON(filepath.Join(m.Root, "selections.json"), &selections)
	}
	salt := make([]byte, 4)
	if _, e := rand.Read(salt); e != nil {
		return "", Report{}, e
	}
	id := time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(salt)
	stage := filepath.Join(m.Root, "revisions", id)
	cv := Converter{Settings: s, Cache: filepath.Join(m.Root, "cache"), Geodata: filepath.Join(m.Root, "geodata"), Selections: selections, RefreshNodes: refreshNodes, RefreshRules: refreshRules, Progress: m.buildObserver}
	r, e := cv.Convert(ctx, source, stage)
	if e != nil {
		m.audit("build_failed", e.Error())
		_ = os.RemoveAll(stage)
		return id, r, e
	}
	// Native validator uses the candidate executable path, but binary path changes are CLI-only.
	if e = m.preserveNative(stage); e != nil {
		return id, r, e
	}
	if m.buildObserver != nil {
		m.buildObserver("validate", "节点与规则转换完成，正在执行 dae 原生校验", r)
	}
	if e = m.validate(ctx, stage); e != nil {
		r.Validation = "failed"
		_ = writeJSON(filepath.Join(stage, "report.json"), r)
		m.prune()
		return id, r, e
	}
	r.Validation = "passed"
	if b, err := os.ReadFile(filepath.Join(stage, "config.dae")); err == nil {
		r.ConfigHash = digest(b)
	}
	if e = writeJSON(filepath.Join(stage, "report.json"), r); e != nil {
		return id, r, e
	}
	for _, g := range r.Groups {
		if g.Type == "select" {
			selections[g.Name] = g.Selected
		}
	}
	for file, v := range map[string]any{"selections.json": selections, "settings.json": s} {
		if e = writeJSON(filepath.Join(stage, file), v); e != nil {
			return id, r, e
		}
	}
	if e = atomicWrite(filepath.Join(stage, "source.yaml"), source, 0600); e != nil {
		return id, r, e
	}
	return id, r, nil
}
func (m *Manager) setCurrent(id string) error {
	if !validRevision(id) {
		return fmt.Errorf("版本 ID 无效")
	}
	tmp := filepath.Join(m.Root, ".next")
	_ = os.Remove(tmp)
	if e := os.Symlink(filepath.Join("revisions", id), tmp); e != nil {
		return e
	}
	if e := os.Rename(tmp, filepath.Join(m.Root, "current")); e != nil {
		_ = os.Remove(tmp)
		return e
	}
	return nil
}
func (m *Manager) activate(ctx context.Context, id string, requireRunning bool) error {
	if !validRevision(id) {
		return fmt.Errorf("版本 ID 无效")
	}
	path := filepath.Join(m.Root, "revisions", id)
	var r Report
	if e := readJSON(filepath.Join(path, "report.json"), &r); e != nil || r.Validation != "passed" {
		return fmt.Errorf("只能应用原生校验通过的版本")
	}
	if e := m.validate(ctx, path); e != nil {
		return e
	}
	old := m.currentID()
	running := m.coreProcess().PID > 0
	if requireRunning && !running {
		return fmt.Errorf("dae 未运行；请先启动服务，或使用 prepare 初始化")
	}
	// Write-ahead journal allows recovery if killed between swapping config and reloading.
	if e := writeJSON(filepath.Join(m.Root, "transaction.json"), M{"old": old, "new": id}); e != nil {
		return e
	}
	if e := m.setCurrent(id); e != nil {
		return e
	}
	if running {
		if e := m.reload(ctx); e != nil {
			if old != "" {
				_ = m.setCurrent(old)
				re := m.reload(ctx)
				if re != nil {
					m.audit("rollback_failed", "旧配置已恢复，重载失败，需检查服务")
					return fmt.Errorf("应用失败，旧配置已恢复但重载仍失败；检查服务")
				}
			}
			_ = os.Remove(filepath.Join(m.Root, "transaction.json"))
			m.audit("rolled_back", "重载失败，已恢复旧配置")
			return fmt.Errorf("重载失败，已回滚旧配置")
		}
	}
	if e := m.restoreInputs(path); e != nil {
		return e
	}
	_ = os.Remove(filepath.Join(m.Root, "transaction.json"))
	m.audit("activated", id)
	if running {
		m.recordRunning()
	}
	m.prune()
	return nil
}
func (m *Manager) restoreInputs(path string) error {
	for _, file := range []string{"source.yaml", "selections.json", "settings.json"} {
		b, e := os.ReadFile(filepath.Join(path, file))
		if e != nil {
			return e
		}
		if e = atomicWrite(filepath.Join(m.Root, file), b, 0600); e != nil {
			return e
		}
	}
	var s Settings
	if e := readJSON(filepath.Join(m.Root, "settings.json"), &s); e != nil {
		return e
	}
	m.mu.Lock()
	m.S = s
	m.mu.Unlock()
	return nil
}
func (m *Manager) recoverTransaction(ctx context.Context) error {
	var t map[string]string
	if e := readJSON(filepath.Join(m.Root, "transaction.json"), &t); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	if old := t["old"]; validRevision(old) {
		if e := m.setCurrent(old); e != nil {
			return e
		}
		if m.coreProcess().PID > 0 {
			if e := m.reload(ctx); e != nil {
				return e
			}
		}
		if e := m.restoreInputs(m.currentDir()); e != nil {
			return e
		}
	} else {
		_ = os.Remove(filepath.Join(m.Root, "current"))
	}
	m.audit("recovered", "恢复中断事务的旧配置")
	return os.Remove(filepath.Join(m.Root, "transaction.json"))
}
func (m *Manager) revisions() []Revision {
	var out []Revision
	dirs, _ := os.ReadDir(filepath.Join(m.Root, "revisions"))
	for _, d := range dirs {
		if !d.IsDir() || !validRevision(d.Name()) {
			continue
		}
		var r Report
		if readJSON(filepath.Join(m.Root, "revisions", d.Name(), "report.json"), &r) == nil {
			out = append(out, Revision{d.Name(), r.Created, len(r.Nodes), d.Name() == m.currentID(), r.Validation})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}
func (m *Manager) prune() {
	revs := m.revisions()
	for i, rev := range revs {
		if i >= 8 && !rev.Active {
			_ = os.RemoveAll(filepath.Join(m.Root, "revisions", rev.ID))
		}
	}
}
func (m *Manager) startJob(kind string, fn func(context.Context) error) (Job, error) {
	m.mu.Lock()
	if m.job.State == "running" {
		m.mu.Unlock()
		return Job{}, fmt.Errorf("已有后台任务正在运行")
	}
	j := Job{ID: fmt.Sprint(time.Now().UnixNano()), Kind: kind, State: "running", Message: "正在执行，请稍候", Started: time.Now()}
	m.job = j
	m.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		unlock, e := m.lock()
		if e == nil {
			defer unlock()
			e = fn(ctx)
		}
		m.mu.Lock()
		m.job.Finished = time.Now()
		m.job.State = "success"
		m.job.Message = "操作已完成"
		if e != nil {
			m.job.State = "failed"
			m.job.Message = e.Error()
		}
		finished := m.job
		var results map[string]Job
		_ = readJSON(filepath.Join(m.Root, "operations.json"), &results)
		if results == nil {
			results = map[string]Job{}
		}
		results[kind] = finished
		_ = writeJSON(filepath.Join(m.Root, "operations.json"), results)
		m.mu.Unlock()
		if e != nil {
			m.audit("job_failed", e.Error())
		}
	}()
	return j, nil
}
