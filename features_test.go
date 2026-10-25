package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestThreeWayNativeMerge(t *testing.T) {
	cases := []struct {
		base, local, new, want string
		conflict               bool
	}{
		{"a\nb\nc\nd\n", "A\nb\nc\nd\n", "a\nb\nc\nD\n", "A\nb\nc\nD\n", false},
		{"a\nb\n", "a\nb\n# user\n", "a\nb\n", "a\nb\n# user\n", false},
		{"a\nb\n", "a\nB\n", "a\nB\n", "a\nB\n", false},
		{"a\nb\n", "a\nB\n", "a\nC\n", "", true},
		{"a\nb\n", "a\nx\nb\n", "a\ny\nb\n", "", true},
		{"a\nb\nc\nd\n", "a\nc\nd\n", "a\nb\nc\nd\ne\n", "a\nc\nd\ne\n", false},
	}
	for i, c := range cases {
		got, e := mergeConfig([]byte(c.base), []byte(c.local), []byte(c.new))
		if (e != nil) != c.conflict || !c.conflict && string(got) != c.want {
			t.Fatalf("case %d: %q %v", i, got, e)
		}
	}
}
func TestNativeOverlayPreservedAndConflictKeepsActive(t *testing.T) {
	m, _ := setup(t)
	rev := buildFixture(t, m)
	if e := m.activate(context.Background(), rev, false); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(m.currentDir(), "config.dae")
	original, _ := os.ReadFile(path)
	local := append(original, []byte("\n# manual comment\n")...)
	_ = atomicWrite(path, local, 0600)
	next := buildFixture(t, m)
	merged, _ := os.ReadFile(filepath.Join(m.Root, "revisions", next, "config.dae"))
	if !strings.HasSuffix(string(merged), "# manual comment\n") {
		t.Fatal("manual edit discarded")
	}
	local = []byte(strings.Replace(string(original), "log_level: info", "log_level: trace", 1))
	_ = atomicWrite(path, local, 0600)
	settings := m.settings()
	settings.LogLevel = "debug"
	if _, _, e := m.build(context.Background(), false, false, nil, nil, settings); e == nil {
		t.Fatal("conflicting settings silently replaced manual edit")
	}
	if m.currentID() != rev {
		t.Fatal("failed update replaced active revision")
	}
}
func TestTelemetryProcessBoundaryAndNetwork(t *testing.T) {
	since := time.Date(2026, 10, 25, 17, 0, 0, 0, time.Local)
	log := `[2026-10-25 16:59:59] DEBUG Connectivity Check last=5ms network=tcp4 node=n_old
[2026-10-25 17:00:01] DEBUG Connectivity Check avg_10=206ms last=210ms mov_avg=103ms network=tcp4 node=n_new
[2026-10-25 17:00:02] DEBUG Connectivity Check Failed err="timeout" network=udp4(DNS) node=n_new
[2026-10-25 17:00:03] INFO Group selects dialer dialer=n_new group=g_auto network=tcp4
[2026-10-25 17:00:04] INFO Group re-selects dialer _new_dialer=n_udp _old_dialer=n_new group=g_auto network=udp4
`
	v := parseTelemetry(log, since)
	if _, ok := v.Core["n_old"]; ok {
		t.Fatal("old process sample exposed")
	}
	if l := v.Core["n_new"]["tcp4"]; !l.OK || l.MS == nil || *l.MS != 210 || *l.Average != 103 {
		t.Fatalf("wrong health value: %+v", l)
	}
	if l := v.Core["n_new"]["udp4"]; l.OK || l.MS != nil {
		t.Fatal("failed health check has a fake zero")
	}
	if v.Exits["g_auto"]["udp4"].Node != "n_udp" {
		t.Fatal("UDP exit lost")
	}
}
func TestNetflixSearchAliasesAndIPInference(t *testing.T) {
	index := NetflixIndex{IPs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}
	for _, line := range []string{"DEBUG 192.0.2.10:1 <-> a.nflxvideo.net:443 network=tcp4", "DEBUG DNS qname=assets.nflximg.net", "DEBUG ip=198.51.100.2 network=tcp4"} {
		got := filterLogs(enrichNetflix(line, index), "netflix", "all", "all", 5)
		if len(got) != 1 {
			t.Fatal("Netflix alias unsearchable")
		}
	}
	if s := enrichNetflix("DEBUG client=198.51.100.2 qname=unrelated.example", index); strings.Contains(s, "Netflix") {
		t.Fatal("source IP mislabeled as destination")
	}
	g := geoBuilder{}
	_ = g.add(id("r_", "netflix_ip"), "ipcidr", []string{"198.51.100.0/24"})
	m, _ := setup(t)
	rev := buildFixture(t, m)
	_ = m.activate(context.Background(), rev, false)
	_ = atomicWrite(filepath.Join(m.currentDir(), "rules-ip.dat"), g.ips, 0600)
	r, _ := m.report()
	r.Providers = append(r.Providers, ProviderInfo{Name: "netflix_ip", Kind: "rules"})
	_ = writeJSON(filepath.Join(m.currentDir(), "report.json"), r)
	if len(m.netflixIndex().IPs) != 1 {
		t.Fatal("DAT matcher did not load Netflix IP prefixes")
	}
}

func TestCompressedCoreRotationSearch(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "dae-2026-10-25T19-00.log.gz")
	f, e := os.Create(old)
	if e != nil {
		t.Fatal(e)
	}
	z := gzip.NewWriter(f)
	_, _ = z.Write([]byte("[2026-10-25 19:00:00] DEBUG 192.0.2.10 <-> nflxvideo.net\n"))
	_ = z.Close()
	_ = f.Close()
	_ = os.WriteFile(filepath.Join(dir, "dae.log"), []byte("[2026-10-25 19:30:00] INFO new process\n"), 0600)
	got := rotatedLogs(filepath.Join(dir, "dae.log"))
	if !strings.Contains(got, "nflxvideo.net") || !strings.Contains(got, "new process") {
		t.Fatal("compressed history excluded")
	}
}
func awaitJob(t *testing.T, m *Manager) Job {
	t.Helper()
	for i := 0; i < 200; i++ {
		m.mu.RLock()
		j := m.job
		m.mu.RUnlock()
		if j.State != "running" {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job timeout")
	return Job{}
}
func TestNativeDraftSeparateAndRejectedApplyKeepsRunning(t *testing.T) {
	m, token := setup(t)
	rev := buildFixture(t, m)
	_ = m.activate(context.Background(), rev, false)
	m.processProbe = func() Process { return Process{PID: 123, Uptime: 30} }
	m.recordRunning()
	before := m.configView()["running"]
	a := &api{m: m, sessions: map[string]session{}, attempts: map[string]attempt{}}
	put := func(value string, apply bool) {
		body, _ := json.Marshal(M{"config": value, "apply": apply})
		r := httptest.NewRequest("PUT", "/api/dae/config", strings.NewReader(string(body)))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("X-DAE-Request", "1")
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, r)
		if w.Code != 202 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	put("invalid dae draft", false)
	if j := awaitJob(t, m); j.State != "success" {
		t.Fatal(j)
	}
	if m.currentID() != rev || m.configView()["running"] != before || m.configView()["draft"] != "invalid dae draft" {
		t.Fatal("saving draft affected running configuration")
	}
	fail := filepath.Join(m.Root, "validate-reject")
	_ = os.WriteFile(fail, []byte("#!/bin/sh\necho 'line 1: invalid dae syntax'\nexit 1\n"), 0700)
	m.S.Dae = fail
	put("invalid dae draft", true)
	if j := awaitJob(t, m); j.State != "failed" {
		t.Fatal(j)
	}
	if m.currentID() != rev || m.configView()["running"] != before {
		t.Fatal("invalid config reached running core")
	}
	var results map[string]Job
	_ = readJSON(filepath.Join(m.Root, "operations.json"), &results)
	if results["dae-config"].State != "failed" {
		t.Fatal("operation result not retained")
	}
}
func TestNativeApplyWithHelper(t *testing.T) {
	if os.Getenv("DAE_MANAGER_HELPER") == "" {
		t.Skip("set DAE_MANAGER_HELPER for parser integration")
	}
	m, _ := setup(t)
	rev := buildFixture(t, m)
	_ = m.activate(context.Background(), rev, false)
	m.processProbe = func() Process { return Process{PID: 9, Uptime: 30} }
	m.reloadAction = func(context.Context) error { return nil }
	data, _ := os.ReadFile(filepath.Join(m.currentDir(), "config.dae"))
	data = append(data, []byte("\n# accepted custom edit\n")...)
	if e := m.applyNative(context.Background(), data); e != nil {
		t.Fatal(e)
	}
	if m.currentID() == rev || !strings.Contains(fmt.Sprint(m.configView()["running"]), "accepted custom edit") {
		t.Fatal("native apply snapshot missing")
	}
	r, e := m.liveReport(context.Background())
	if e != nil || len(r.Nodes) != 1 {
		t.Fatal("native inventory failed", e)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "vless://") {
		t.Fatal("native report leaks URI")
	}
}

func TestStaleNativeDraftCannotOverwriteNewSelection(t *testing.T) {
	m, token := setup(t)
	old := buildFixture(t, m)
	_ = m.activate(context.Background(), old, false)
	original, _ := os.ReadFile(filepath.Join(m.currentDir(), "config.dae"))
	newer := buildFixture(t, m)
	_ = m.activate(context.Background(), newer, false)
	body, _ := json.Marshal(M{"config": string(original), "apply": true, "base_revision": old})
	req := httptest.NewRequest("PUT", "/api/dae/config", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-DAE-Request", "1")
	w := httptest.NewRecorder()
	a := &api{m: m, sessions: map[string]session{}, attempts: map[string]attempt{}}
	a.handler().ServeHTTP(w, req)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	j := awaitJob(t, m)
	if j.State != "failed" || m.currentID() != newer {
		t.Fatal("stale draft replaced newer revision")
	}
	v := m.configView()
	if v["draft_stale"] != true || v["draft_revision"] != old {
		t.Fatal("stale draft not identified")
	}
}
