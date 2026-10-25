package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func helperExecutable() string {
	if value := os.Getenv("DAE_MANAGER_HELPER"); value != "" {
		return value
	}
	return "/usr/local/lib/dae-manager/dae-helper"
}

type NativeNode struct {
	ID   string `json:"id"`
	URI  string `json:"uri"`
	Type string `json:"type"`
}
type NativeGroup struct {
	ID      string   `json:"id"`
	Policy  string   `json:"policy"`
	Members []string `json:"members"`
	Known   bool     `json:"known"`
}
type NativeRule struct {
	Expression string `json:"expression"`
	Outbound   string `json:"outbound"`
}
type Inventory struct {
	Nodes    []NativeNode    `json:"nodes"`
	Groups   []NativeGroup   `json:"groups"`
	Rules    []NativeRule    `json:"rules"`
	Global   json.RawMessage `json:"global"`
	Includes bool            `json:"includes"`
}

func inspectConfig(ctx context.Context, data []byte) (Inventory, error) {
	var inv Inventory
	cmd := exec.CommandContext(ctx, helperExecutable(), "inspect")
	cmd.Stdin = bytes.NewReader(data)
	out, e := cmd.Output()
	if e != nil {
		return inv, fmt.Errorf("无法读取 dae 配置结构，请先运行原生校验并检查 dae-helper")
	}
	e = json.Unmarshal(out, &inv)
	return inv, e
}

// A line based three-way merge preserves local edits across generated updates.
// Ambiguous changes stop the update before activation.
type lineEdit struct {
	start, end int
	lines      []string
}

func diffLines(a, b []string) ([]lineEdit, error) {
	if len(a)*len(b) > 16000000 {
		return nil, fmt.Errorf("配置过大，无法安全合并手工修改")
	}
	width := len(b) + 1
	dp := make([]int32, (len(a)+1)*width)
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i*width+j] = 1 + dp[(i+1)*width+j+1]
			} else {
				dp[i*width+j] = max(dp[(i+1)*width+j], dp[i*width+j+1])
			}
		}
	}
	var out []lineEdit
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		if i < len(a) && j < len(b) && a[i] == b[j] {
			i++
			j++
			continue
		}
		edit := lineEdit{start: i}
		for i < len(a) || j < len(b) {
			if i < len(a) && j < len(b) && a[i] == b[j] {
				break
			}
			if j < len(b) && (i == len(a) || dp[i*width+j+1] >= dp[(i+1)*width+j]) {
				edit.lines = append(edit.lines, b[j])
				j++
			} else {
				i++
			}
		}
		edit.end = i
		out = append(out, edit)
	}
	return out, nil
}
func mergeConfig(base, local, generated []byte) ([]byte, error) {
	if bytes.Equal(base, local) {
		return generated, nil
	}
	if bytes.Equal(base, generated) || bytes.Equal(local, generated) {
		return local, nil
	}
	a := strings.Split(string(base), "\n")
	l, e := diffLines(a, strings.Split(string(local), "\n"))
	if e != nil {
		return nil, e
	}
	r, e := diffLines(a, strings.Split(string(generated), "\n"))
	if e != nil {
		return nil, e
	}
	var out []string
	pos, i, j := 0, 0, 0
	for i < len(l) || j < len(r) {
		var x lineEdit
		if i < len(l) && j < len(r) {
			p, q := l[i], r[j]
			if p.start == q.start && p.end == q.end && strings.Join(p.lines, "\n") == strings.Join(q.lines, "\n") {
				x = p
				i++
				j++
			} else if p.start <= q.end && q.start <= p.end {
				return nil, fmt.Errorf("手工 dae 配置与自动更新在原配置第 %d 行附近冲突；当前配置保持运行，请调整草稿后重新应用", min(p.start, q.start)+1)
			} else if p.start < q.start {
				x = p
				i++
			} else {
				x = q
				j++
			}
		} else if i < len(l) {
			x = l[i]
			i++
		} else {
			x = r[j]
			j++
		}
		out = append(out, a[pos:x.start]...)
		out = append(out, x.lines...)
		pos = x.end
	}
	out = append(out, a[pos:]...)
	return []byte(strings.Join(out, "\n")), nil
}
func (m *Manager) preserveNative(stage string) error {
	fresh, e := os.ReadFile(filepath.Join(stage, "config.dae"))
	if e != nil {
		return e
	}
	if e = atomicWrite(filepath.Join(stage, "baseline-config.dae"), fresh, 0600); e != nil {
		return e
	}
	old, e := os.ReadFile(filepath.Join(m.currentDir(), "config.dae"))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	base, e := os.ReadFile(filepath.Join(m.currentDir(), "baseline-config.dae"))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	merged, e := mergeConfig(base, old, fresh)
	if e != nil {
		return e
	}
	return atomicWrite(filepath.Join(stage, "config.dae"), merged, 0600)
}
func (m *Manager) applyNative(ctx context.Context, data []byte) error {
	if len(data) == 0 || len(data) > 1<<20 {
		return fmt.Errorf("dae 配置必须介于 1 字节和 1 MiB")
	}
	salt := make([]byte, 4)
	if _, e := rand.Read(salt); e != nil {
		return e
	}
	rev := time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(salt)
	stage := filepath.Join(m.Root, "revisions", rev)
	if e := os.MkdirAll(stage, 0700); e != nil {
		return e
	}
	entries, e := os.ReadDir(m.currentDir())
	if e != nil {
		return e
	}
	for _, f := range entries {
		if f.IsDir() {
			continue
		}
		if e = linkOrCopy(filepath.Join(m.currentDir(), f.Name()), filepath.Join(stage, f.Name())); e != nil {
			return e
		}
	}
	if _, e = os.Stat(filepath.Join(stage, "baseline-config.dae")); os.IsNotExist(e) {
		if e = linkOrCopy(filepath.Join(m.currentDir(), "config.dae"), filepath.Join(stage, "baseline-config.dae")); e != nil {
			return e
		}
	}
	if e = atomicWrite(filepath.Join(stage, "config.dae"), data, 0600); e != nil {
		return e
	}
	report, e := m.report()
	if e != nil {
		return e
	}
	report.Created = time.Now()
	report.Validation = "failed"
	report.ConfigHash = digest(data)
	// Do not inherit a passed report while a candidate is being validated.
	if e = writeJSON(filepath.Join(stage, "report.json"), report); e != nil {
		return e
	}
	if e = m.validate(ctx, stage); e != nil {
		diagnostic, _ := os.ReadFile(filepath.Join(stage, "validation-error.txt"))
		_ = atomicWrite(filepath.Join(m.Root, "last-native-validation.txt"), diagnostic, 0600)
		_ = atomicWrite(filepath.Join(m.Root, "last-native-validation.hash"), []byte(digest(data)), 0600)
		return e
	}
	_ = os.Remove(filepath.Join(m.Root, "last-native-validation.txt"))
	inv, err := inspectConfig(ctx, data)
	if err != nil {
		return err
	}
	var global struct {
		LogLevel string `json:"log_level"`
	}
	_ = json.Unmarshal(inv.Global, &global)
	settings := m.settings()
	if in(global.LogLevel, []string{"error", "warn", "info", "debug", "trace"}) {
		settings.LogLevel = global.LogLevel
	}
	if e = writeJSON(filepath.Join(stage, "settings.json"), settings); e != nil {
		return e
	}
	report.Validation = "passed"
	if e = writeJSON(filepath.Join(stage, "report.json"), report); e != nil {
		return e
	}
	if e = m.activate(ctx, rev, false); e != nil {
		return e
	}
	if m.coreProcess().PID == 0 {
		return m.service(ctx, "start")
	}
	return nil
}

func (m *Manager) configView() M {
	current, _ := os.ReadFile(filepath.Join(m.currentDir(), "config.dae"))
	draft, e := os.ReadFile(filepath.Join(m.Root, "draft.dae"))
	if e != nil {
		draft = current
	}
	p := m.coreProcess()
	running := ""
	note := "核心未运行；下次启动的配置可用于编辑"
	var loaded struct {
		PID      int    `json:"pid"`
		Config   string `json:"config"`
		Revision string `json:"revision"`
	}
	_ = readJSON(filepath.Join(m.Root, "running-config.json"), &loaded)
	if p.PID > 0 {
		if loaded.PID == p.PID {
			running = loaded.Config
			note = "最近成功加载的配置快照"
		} else if st, e := os.Stat(filepath.Join(m.currentDir(), "config.dae")); e == nil && st.ModTime().Before(time.Now().Add(-time.Duration(p.Uptime*float64(time.Second))).Add(time.Second)) {
			running = string(current)
			note = "根据本次进程启动时间确认的配置"
		} else {
			note = "核心正在运行，但尚未确认其加载快照；请通过面板应用配置"
		}
	}
	diagnostic, _ := os.ReadFile(filepath.Join(m.Root, "last-native-validation.txt"))
	failedHash, _ := os.ReadFile(filepath.Join(m.Root, "last-native-validation.hash"))
	if string(failedHash) != digest(draft) {
		diagnostic = nil
	}
	baseRevision := m.currentID()
	var draftState struct {
		Hash         string `json:"hash"`
		BaseRevision string `json:"base_revision"`
	}
	if readJSON(filepath.Join(m.Root, "draft-state.json"), &draftState) == nil && draftState.Hash == digest(draft) {
		baseRevision = draftState.BaseRevision
	} else if string(draft) != string(current) {
		baseRevision = "unknown"
	}
	return M{"draft_revision": baseRevision, "draft_stale": baseRevision != m.currentID(), "validation_error": string(diagnostic), "draft": string(draft), "running": running, "active": string(current), "note": note, "pid": p.PID, "revision": m.currentID()}
}
func (m *Manager) recordRunning() {
	p := m.coreProcess()
	if p.PID == 0 {
		return
	}
	b, e := os.ReadFile(filepath.Join(m.currentDir(), "config.dae"))
	if e == nil {
		_ = writeJSON(filepath.Join(m.Root, "running-config.json"), M{"pid": p.PID, "config": string(b), "revision": m.currentID(), "loaded_at": time.Now()})
	}
}
