package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Latency struct {
	OK          bool      `json:"ok"`
	MS          *int64    `json:"ms"`
	Average     *int64    `json:"average_ms,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
	Message     string    `json:"message"`
	WarmMS      *int64    `json:"warm_ms,omitempty"`
	WarmReused  bool      `json:"warm_reused,omitempty"`
	WarmMessage string    `json:"warm_message,omitempty"`
	DialMS      int64     `json:"dial_ms,omitempty"`
	TLSMS       int64     `json:"tls_ms,omitempty"`
	ResponseMS  int64     `json:"response_ms,omitempty"`
	URL         string    `json:"url,omitempty"`
	HTTP        string    `json:"http,omitempty"`
}
type ExitObservation struct {
	Node      string    `json:"node"`
	CheckedAt time.Time `json:"checked_at"`
}
type Telemetry struct {
	Core   map[string]map[string]Latency         `json:"core"`
	Manual map[string]Latency                    `json:"manual"`
	Exits  map[string]map[string]ExitObservation `json:"exits"`
	Synced time.Time                             `json:"synced"`
	PID    int                                   `json:"pid"`
	Note   string                                `json:"note"`
}

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")
var fieldRE = regexp.MustCompile(`([\w]+)=("(?:[^"\\]|\\.)*"|[^\s]+)`)

func fieldsLog(line string) map[string]string {
	v := map[string]string{}
	for _, m := range fieldRE.FindAllStringSubmatch(line, -1) {
		s := m[2]
		if strings.HasPrefix(s, `"`) {
			if t, e := strconv.Unquote(s); e == nil {
				s = t
			}
		}
		v[m[1]] = s
	}
	return v
}
func logTime(line string) time.Time {
	if len(line) > 21 && line[0] == '[' {
		t, _ := time.ParseInLocation("2006-01-02 15:04:05", line[1:20], time.Local)
		return t
	}
	return time.Time{}
}
func rotatedLogs(path string) string {
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(path), strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))+"*"+filepath.Ext(path)+"*"))
	if len(files) == 0 {
		files = []string{path}
	}
	sort.Slice(files, func(i, j int) bool {
		a, _ := os.Stat(files[i])
		b, _ := os.Stat(files[j])
		return a != nil && b != nil && a.ModTime().Before(b.ModTime())
	})
	if len(files) > 3 {
		files = files[len(files)-3:]
	}
	var out strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, ".gz") {
			if file, e := os.Open(f); e == nil {
				if reader, e := gzip.NewReader(file); e == nil {
					b, _ := io.ReadAll(io.LimitReader(reader, (5<<20)+65536))
					out.Write(b)
					reader.Close()
				}
				file.Close()
			}
		} else {
			out.WriteString(tail(f, 5<<20))
		}
		out.WriteByte('\n')
	}
	return ansiRE.ReplaceAllString(out.String(), "")
}
func parseTelemetry(logs string, since time.Time) Telemetry {
	t := Telemetry{Core: map[string]map[string]Latency{}, Manual: map[string]Latency{}, Exits: map[string]map[string]ExitObservation{}, Synced: time.Now()}
	for _, line := range strings.Split(logs, "\n") {
		at := logTime(line)
		if at.IsZero() || at.Before(since) {
			continue
		}
		f := fieldsLog(line)
		network := f["network"]
		// dae labels DNS-based UDP probes as udp4(DNS)/udp6(DNS).
		network, _, _ = strings.Cut(network, "(")
		if strings.Contains(line, "Connectivity Check") && f["node"] != "" && network != "" {
			id := f["node"]
			if t.Core[id] == nil {
				t.Core[id] = map[string]Latency{}
			}
			l := Latency{CheckedAt: at, Message: "核心健康检查失败"}
			if d, e := time.ParseDuration(f["last"]); e == nil {
				v := d.Milliseconds()
				l.MS = &v
				l.OK = true
				l.Message = "核心健康检查"
			}
			if d, e := time.ParseDuration(f["mov_avg"]); e == nil {
				v := d.Milliseconds()
				l.Average = &v
			}
			t.Core[id][network] = l
		}
		if strings.Contains(line, "Group selects dialer") || strings.Contains(line, "Group re-selects dialer") {
			node := f["dialer"]
			if f["_new_dialer"] != "" {
				node = f["_new_dialer"]
			}
			if f["group"] != "" && network != "" && node != "" {
				if t.Exits[f["group"]] == nil {
					t.Exits[f["group"]] = map[string]ExitObservation{}
				}
				t.Exits[f["group"]][network] = ExitObservation{node, at}
			}
		}
		// Connection records are the most direct evidence of an actual final exit.
		if f["outbound"] != "" && f["dialer"] != "" && network != "" && strings.Contains(line, "<->") {
			if t.Exits[f["outbound"]] == nil {
				t.Exits[f["outbound"]] = map[string]ExitObservation{}
			}
			t.Exits[f["outbound"]][network] = ExitObservation{f["dialer"], at}
		}
	}
	return t
}
func (m *Manager) telemetry(force bool) Telemetry {
	m.teleMu.Lock()
	defer m.teleMu.Unlock()
	p := m.coreProcess()
	if !force && time.Since(m.tele.Synced) < 4*time.Second && m.tele.PID == p.PID {
		return m.tele
	}
	since := time.Now().Add(-time.Duration(p.Uptime * float64(time.Second))).Add(-time.Second)
	t := parseTelemetry(rotatedLogs(m.settings().LogPath), since)
	t.PID = p.PID
	_ = readJSON(filepath.Join(m.Root, "manual-latency.json"), &t.Manual)
	if t.Manual == nil {
		t.Manual = map[string]Latency{}
	}
	t.Note = "核心值是 dae 健康检查耗时，不是 ping；UDP 为 DNS 探测。手动值分首次请求（含建连及握手）和第二次请求，只有明确复用连接时才标为“复用”。可展开耗时组成与测试地址；缺失数据留空。"
	m.tele = t
	return t
}
func (m *Manager) inventory(ctx context.Context) (Inventory, error) {
	m.invMu.Lock()
	defer m.invMu.Unlock()
	rev := m.currentID()
	if m.invRevision == rev && rev != "" {
		return m.inv, nil
	}
	b, e := os.ReadFile(filepath.Join(m.currentDir(), "config.dae"))
	if e != nil {
		return Inventory{}, e
	}
	inv, e := inspectConfig(ctx, b)
	if e == nil {
		m.inv = inv
		m.invRevision = rev
	}
	return inv, e
}
func (m *Manager) manualProbe(ctx context.Context, ids []string) error {
	inv, e := m.inventory(ctx)
	if e != nil {
		return e
	}
	nodes := []NativeNode{}
	for _, n := range inv.Nodes {
		if len(ids) == 0 || in(n.ID, ids) {
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		return fmt.Errorf("未找到可测试的节点")
	}
	if len(nodes) > 2048 {
		return fmt.Errorf("单次最多测试 2048 个节点")
	}
	data, _ := json.Marshal(M{"nodes": nodes, "global": inv.Global, "dns": m.settings().DNSBind})
	cmd := exec.CommandContext(ctx, helperExecutable(), "probe", "--workers", "4")
	cmd.Stdin = bytes.NewReader(data)
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		return e
	}
	if e = cmd.Start(); e != nil {
		return fmt.Errorf("手动测速组件启动失败")
	}
	results := map[string]Latency{}
	_ = readJSON(filepath.Join(m.Root, "manual-latency.json"), &results)
	if results == nil {
		results = map[string]Latency{}
	}
	scanner := bufio.NewScanner(pipe)
	count := 0
	for scanner.Scan() {
		var result struct {
			ID string `json:"id"`
			Latency
		}
		if json.Unmarshal(scanner.Bytes(), &result) != nil || result.ID == "" {
			continue
		}
		results[result.ID] = result.Latency
		count++
		if e = writeJSON(filepath.Join(m.Root, "manual-latency.json"), results); e != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return e
		}
		m.mu.Lock()
		m.job.Message = fmt.Sprintf("手动测速 %d / %d；结果已实时保存", count, len(nodes))
		m.mu.Unlock()
		m.teleMu.Lock()
		m.tele.Synced = time.Time{}
		m.teleMu.Unlock()
	}
	err := cmd.Wait()
	if scanner.Err() != nil || err != nil || count != len(nodes) {
		return fmt.Errorf("测速未全部完成；已保留 %d / %d 个结果", count, len(nodes))
	}
	return nil
}
func gateway() string {
	b, _ := os.ReadFile("/proc/net/route")
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 3 && f[1] == "00000000" {
			n, e := strconv.ParseUint(f[2], 16, 32)
			if e == nil {
				return fmt.Sprintf("%d.%d.%d.%d", n&255, (n>>8)&255, (n>>16)&255, n>>24)
			}
		}
	}
	return "未知"
}
func serviceState(ctx context.Context) M {
	result := M{"active": "unknown", "autostart": "unknown"}
	if _, e := os.Stat("/etc/init.d/dae-managed"); e == nil {
		if _, e = command(ctx, "/etc/init.d/dae-managed", "enabled"); e == nil {
			result["autostart"] = "enabled"
		} else {
			result["autostart"] = "disabled"
		}
		return result
	}
	out, e := command(ctx, "systemctl", "show", "dae-managed.service", "--property=ActiveState,SubState,UnitFileState")
	if e == nil {
		for _, line := range strings.Split(string(out), "\n") {
			k, v, _ := strings.Cut(line, "=")
			switch k {
			case "ActiveState":
				result["active"] = v
			case "SubState":
				result["sub"] = v
			case "UnitFileState":
				result["autostart"] = v
			}
		}
	}
	return result
}
