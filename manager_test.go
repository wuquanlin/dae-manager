package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture() M {
	return M{"mode": "rule", "dns": M{"ipv6": false, "nameserver": []any{"https://223.5.5.5/dns-query#DIRECT"}}, "proxies": []any{M{"name": "香港 HK", "type": "vless", "server": "127.0.0.1", "port": 443, "uuid": "00000000-0000-4000-8000-000000000001", "tls": true}}, "proxy-groups": []any{M{"name": "自动", "type": "url-test", "include-all": true, "filter": "(?=.*(HK|港))^((?!(US|美)).)*$"}, M{"name": "默认", "type": "select", "proxies": []any{"自动", "DIRECT"}}}, "rules": []any{"DOMAIN-SUFFIX,example.org,默认", "MATCH,DIRECT"}}
}
func setup(t *testing.T) (*Manager, string) {
	t.Helper()
	root := t.TempDir()
	m, e := openManager(root)
	if e != nil {
		t.Fatal(e)
	}
	s := defaultSettings(root)
	s.Dae = "/bin/true"
	s.AutoUpdate = false
	token, e := m.init("", s)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		if e = atomicWrite(filepath.Join(root, "geodata", name), []byte{}, 0600); e != nil {
			t.Fatal(e)
		}
	}
	b, _ := yaml.Marshal(fixture())
	if e = atomicWrite(filepath.Join(root, "source.yaml"), b, 0600); e != nil {
		t.Fatal(e)
	}
	return m, token
}
func buildFixture(t *testing.T, m *Manager) string {
	t.Helper()
	id, _, e := m.build(context.Background(), false, false, nil, nil, m.settings())
	if e != nil {
		t.Fatal(e)
	}
	return id
}
func TestConvertPreservesSelectionsAndRuleOrder(t *testing.T) {
	m, _ := setup(t)
	id := buildFixture(t, m)
	var r Report
	if e := readJSON(filepath.Join(m.Root, "revisions", id, "report.json"), &r); e != nil {
		t.Fatal(e)
	}
	if len(r.Nodes) != 1 || len(r.Groups) != 2 || len(r.Rules) != 2 {
		t.Fatal("counts differ")
	}
	if r.Rules[0].Target != "默认" || r.Rules[1].Resolved != "direct" {
		t.Fatal("rule ordering or fallback changed")
	}
	if r.Groups[0].Members[0] != "香港 HK" {
		t.Fatal("lookahead filter lost member")
	}
	source, _ := os.ReadFile(filepath.Join(m.Root, "source.yaml"))
	id, _, e := m.build(context.Background(), false, false, source, map[string]string{"默认": "DIRECT"}, m.settings())
	if e != nil {
		t.Fatal(e)
	}
	var r2 Report
	_ = readJSON(filepath.Join(m.Root, "revisions", id, "report.json"), &r2)
	if r2.Rules[0].Resolved != "direct" {
		t.Fatal("manual DIRECT selection was not preserved")
	}
}
func TestDisappearingChoiceStopsUpdate(t *testing.T) {
	m, _ := setup(t)
	_, _, e := m.build(context.Background(), false, false, nil, map[string]string{"默认": "已删除节点"}, m.settings())
	if e == nil {
		t.Fatal("must reject stale selection")
	}
}
func TestEmptySubscriptionDoesNotReplaceCurrent(t *testing.T) {
	m, _ := setup(t)
	old := buildFixture(t, m)
	if e := m.activate(context.Background(), old, false); e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "proxies: []\n") }))
	defer server.Close()
	c := fixture()
	c["proxies"] = []any{}
	c["proxy-providers"] = M{"Airport": M{"type": "http", "url": server.URL}}
	b, _ := yaml.Marshal(c)
	_, _, e := m.build(context.Background(), true, false, b, nil, m.settings())
	if e == nil {
		t.Fatal("empty subscription accepted")
	}
	if m.currentID() != old {
		t.Fatal("active config changed")
	}
}
func TestInvalidRuleIsNotSilentlyDropped(t *testing.T) {
	m, _ := setup(t)
	c := fixture()
	c["rules"] = []any{"UNKNOWN,example.org,默认", "MATCH,DIRECT"}
	b, _ := yaml.Marshal(c)
	if _, _, e := m.build(context.Background(), false, false, b, nil, m.settings()); e == nil {
		t.Fatal("unsupported rule accepted")
	}
}
func TestGroupCycleAndMissingTarget(t *testing.T) {
	m, _ := setup(t)
	for _, choices := range [][]any{{"默认"}, {"missing"}} {
		c := fixture()
		c["proxy-groups"] = []any{M{"name": "默认", "type": "select", "proxies": choices}}
		b, _ := yaml.Marshal(c)
		if _, _, e := m.build(context.Background(), false, false, b, nil, m.settings()); e == nil {
			t.Fatal("invalid group references accepted")
		}
	}
}
func TestReloadFailureRollsBack(t *testing.T) {
	m, _ := setup(t)
	old := buildFixture(t, m)
	if e := m.activate(context.Background(), old, false); e != nil {
		t.Fatal(e)
	}
	next := buildFixture(t, m)
	m.processProbe = func() Process { return Process{PID: 100} }
	calls := 0
	m.reloadAction = func(context.Context) error {
		calls++
		if calls == 1 {
			return fmt.Errorf("simulated failure")
		}
		return nil
	}
	if e := m.activate(context.Background(), next, true); e == nil {
		t.Fatal("failed reload accepted")
	}
	if m.currentID() != old || calls != 2 {
		t.Fatalf("rollback failed, calls=%d", calls)
	}
	if _, e := os.Stat(filepath.Join(m.Root, "transaction.json")); !os.IsNotExist(e) {
		t.Fatal("journal not cleared")
	}
}
func TestInterruptedTransactionRecovery(t *testing.T) {
	m, _ := setup(t)
	old := buildFixture(t, m)
	if e := m.activate(context.Background(), old, false); e != nil {
		t.Fatal(e)
	}
	next := buildFixture(t, m)
	_ = writeJSON(filepath.Join(m.Root, "transaction.json"), M{"old": old, "new": next})
	_ = m.setCurrent(next)
	if e := m.recoverTransaction(context.Background()); e != nil {
		t.Fatal(e)
	}
	if m.currentID() != old {
		t.Fatal("did not recover previous revision")
	}
}
func TestBadNativeValidationKeepsOld(t *testing.T) {
	m, _ := setup(t)
	old := buildFixture(t, m)
	_ = m.activate(context.Background(), old, false)
	m.S.Dae = "/bin/false"
	if _, _, e := m.build(context.Background(), false, false, nil, nil, m.settings()); e == nil {
		t.Fatal("native failure ignored")
	}
	if m.currentID() != old {
		t.Fatal("active revision changed")
	}
}
func TestConcurrentOperationsLocked(t *testing.T) {
	m, _ := setup(t)
	unlock, e := m.lock()
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	if second, e := m.lock(); e == nil {
		second()
		t.Fatal("concurrent operation allowed")
	}
}
func TestAuthCSRFAndSecretRedaction(t *testing.T) {
	m, token := setup(t)
	rev := buildFixture(t, m)
	_ = m.activate(context.Background(), rev, false)
	a := &api{m: m, sessions: map[string]session{}, attempts: map[string]attempt{}}
	h := a.handler()
	request := func(method, path, body, auth, origin, mark string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", auth)
		r.Header.Set("Origin", origin)
		r.Header.Set("X-DAE-Request", mark)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/report", "", "", "", ""); w.Code != 401 {
		t.Fatal("unauthorized report readable")
	}
	if w := request("GET", "/api/report", "", "Bearer "+token, "https://attacker.example", ""); w.Code != 403 {
		t.Fatal("cross-site origin accepted")
	}
	if w := request("POST", "/api/service", `{"action":"stop"}`, "Bearer "+token, "", ""); w.Code != 403 {
		t.Fatal("missing request marker accepted")
	}
	w := request("GET", "/api/report", "", "Bearer "+token, "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "vless://") || strings.Contains(w.Body.String(), "00000000-0000-4000") {
		t.Fatal("report leaks node secrets")
	}
	w = request("PUT", "/api/settings", `{"dae":"/bin/evil"}`, "Bearer "+token, "", "1")
	if w.Code != 400 {
		t.Fatal("binary path editable via API")
	}
	w = request("POST", "/api/login", `{"token":"`+token+`"}`, "", "", "")
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatal("login failed")
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
}
func TestLogSearchAndSchedule(t *testing.T) {
	lines := filterLogs("INFO dns qname=example.org IP=1.2.3.4\nDEBUG routing example.org direct\nINFO dns other.org", "example.org 1.2.3.4", "dns", "all", 5)
	if len(lines) != 1 {
		t.Fatal("AND keyword filtering broken")
	}
	s := defaultSettings("")
	s.AutoUpdate = true
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	if !due(now, s, ScheduleState{}) {
		t.Fatal("daily schedule not due in Shanghai")
	}
	state := ScheduleState{Day: "2026-10-25", Attempts: 1, LastAttempt: now.Add(-time.Minute), Error: "failed"}
	if due(now, s, state) {
		t.Fatal("retry too soon")
	}
	state.LastAttempt = now.Add(-11 * time.Minute)
	if !due(now, s, state) {
		t.Fatal("retry not due")
	}
	state.Attempts = 3
	if due(now, s, state) {
		t.Fatal("retry limit ignored")
	}
}
func TestPortHoppingAndEncodedPasswords(t *testing.T) {
	r := Report{}
	uri, e := nodeURI(M{"name": "hy2", "type": "hysteria2", "server": "127.0.0.1", "port": 443, "ports": "20000-30000", "password": "a:b@#"}, &r)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(uri, "20000-30000") || !strings.Contains(uri, "a%3Ab%40%23") {
		t.Fatal("port range or password corrupted")
	}
	typ, val := domainPattern("+.example.org")
	if typ != 2 || val != "example.org" {
		t.Fatal("suffix semantics lost")
	}
	typ, val = domainPattern(".example.org")
	if typ != 1 || !strings.Contains(val, "^.+") {
		t.Fatal("subdomain-only semantics lost")
	}
}

type captureDNS struct{ msg *dns.Msg }

func (c *captureDNS) LocalAddr() net.Addr  { return netAddr("127.0.0.1:5353") }
func (c *captureDNS) RemoteAddr() net.Addr { return netAddr("127.0.0.1:1234") }

// DNS ResponseWriter uses net.Addr exactly (implemented below via adapter).
type netAddr string

func (a netAddr) Network() string                 { return "udp" }
func (a netAddr) String() string                  { return string(a) }
func (c *captureDNS) WriteMsg(m *dns.Msg) error   { c.msg = m; return nil }
func (c *captureDNS) Write(b []byte) (int, error) { return len(b), nil }
func (c *captureDNS) Close() error                { return nil }
func (c *captureDNS) TsigStatus() error           { return nil }
func (c *captureDNS) TsigTimersOnly(bool)         {}
func (c *captureDNS) Hijack()                     {}
func TestNativeMRSAndDATIntegration(t *testing.T) {
	dae := os.Getenv("DAE_TEST_BINARY")
	helper := os.Getenv("MRS_TEST_BINARY")
	if dae == "" || helper == "" {
		t.Skip("set DAE_TEST_BINARY and MRS_TEST_BINARY for official binary integration")
	}
	m, _ := setup(t)
	m.S.Dae = dae
	m.S.Mihomo = helper
	path := t.TempDir()
	source := filepath.Join(path, "domains.txt")
	mrs := filepath.Join(path, "domains.mrs")
	_ = os.WriteFile(source, []byte("+.example.org\n.only-subdomains.org\n*.wild.org\n"), 0600)
	if out, e := exec.Command(helper, "convert-ruleset", "domain", "text", source, mrs).CombinedOutput(); e != nil {
		t.Fatalf("fixture encode: %v %s", e, out)
	}
	data, e := os.ReadFile(mrs)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(data) }))
	defer server.Close()
	c := fixture()
	c["rule-providers"] = M{"fixture": M{"type": "http", "behavior": "domain", "format": "mrs", "url": server.URL}}
	c["rules"] = []any{"RULE-SET,fixture,默认", "MATCH,DIRECT"}
	b, _ := yaml.Marshal(c)
	id, r, e := m.build(context.Background(), true, true, b, nil, m.settings())
	if e != nil {
		t.Fatal(e)
	}
	if r.Validation != "passed" {
		t.Fatal("not validated")
	}
	cfg, _ := os.ReadFile(filepath.Join(m.Root, "revisions", id, "config.dae"))
	if !bytes.Contains(cfg, []byte("rules-site.dat:")) {
		t.Fatal("custom DAT reference missing")
	}
}

// Keep compile-time checks for HTTP helpers used in integration tests.
func TestStaticHostsDNS(t *testing.T) {
	m, _ := setup(t)
	rev := buildFixture(t, m)
	if e := m.activate(context.Background(), rev, false); e != nil {
		t.Fatal(e)
	}
	if e := writeJSON(filepath.Join(m.currentDir(), "hosts.json"), M{"internal.example.org": "192.0.2.31"}); e != nil {
		t.Fatal(e)
	}
	req := new(dns.Msg)
	req.SetQuestion("internal.example.org.", dns.TypeA)
	w := &captureDNS{}
	m.dnsHandler(w, req)
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatal("static host A response missing")
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok || a.A.String() != "192.0.2.31" {
		t.Fatal("wrong static host response")
	}
	req.SetQuestion("internal.example.org.", dns.TypeAAAA)
	m.dnsHandler(w, req)
	if len(w.msg.Answer) != 0 {
		t.Fatal("IPv4 static host leaked AAAA")
	}
}
