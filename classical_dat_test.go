package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type datField struct {
	number, integer uint64
	data            []byte
}

func readDATFields(t *testing.T, b []byte) (out []datField) {
	t.Helper()
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			t.Fatal("invalid protobuf tag")
		}
		b = b[n:]
		f := datField{number: tag >> 3}
		v, n := binary.Uvarint(b)
		if n <= 0 {
			t.Fatal("invalid protobuf value")
		}
		b = b[n:]
		switch tag & 7 {
		case 0:
			f.integer = v
		case 2:
			if v > uint64(len(b)) {
				t.Fatal("truncated DAT field")
			}
			f.data = b[:v]
			b = b[v:]
		default:
			t.Fatal("unexpected protobuf wire type")
		}
		out = append(out, f)
	}
	return
}

func TestClassicalDATPreservesDomainKindsAndIPPrefixes(t *testing.T) {
	s := compiledSet{ID: "mixed", Lines: []string{"DOMAIN,one.example.org", "DOMAIN-SUFFIX,example.org", "DOMAIN-KEYWORD,sharepoint", "DOMAIN-REGEX,^test[0-9]+\\.example$", "IP-CIDR,10.1.2.3/8", "IP-CIDR6,fd00::/8"}}
	g := geoBuilder{}
	packed, err := g.packClassical(&s)
	if err != nil || !packed || s.PackedDomains != 4 || s.PackedIPs != 2 {
		t.Fatalf("packing failed: %+v %v", s, err)
	}
	site := readDATFields(t, readDATFields(t, g.sites)[0].data)
	var kinds []uint64
	var values []string
	for _, f := range site {
		if f.number != 2 {
			continue
		}
		domain := readDATFields(t, f.data)
		kinds = append(kinds, domain[0].integer)
		values = append(values, string(domain[1].data))
	}
	if !reflect.DeepEqual(kinds, []uint64{3, 2, 0, 1}) || !reflect.DeepEqual(values, []string{"one.example.org", "example.org", "sharepoint", "^test[0-9]+\\.example$"}) {
		t.Fatalf("domain semantics changed: %v %v", kinds, values)
	}
	ip := readDATFields(t, readDATFields(t, g.ips)[0].data)
	var prefixes []datField
	for _, f := range ip {
		if f.number == 2 {
			prefixes = append(prefixes, readDATFields(t, f.data)...)
		}
	}
	if !bytes.Equal(prefixes[0].data, []byte{10, 0, 0, 0}) || prefixes[1].integer != 8 || len(prefixes[2].data) != 16 || prefixes[2].data[0] != 0xfd || prefixes[3].integer != 8 {
		t.Fatal("CIDR boundaries changed")
	}
	s.Behavior = "classical"
	expr, err := expressions("RULE-SET", "mixed", map[string]compiledSet{"mixed": s})
	if err != nil || len(expr) != 2 {
		t.Fatalf("mixed set must emit two references: %v %v", expr, err)
	}
}

func TestClassicalDATKeepsNonDATConditionsInline(t *testing.T) {
	s := compiledSet{Behavior: "classical", ID: "mixed", Lines: []string{"DOMAIN-SUFFIX,example.org", "SRC-IP-CIDR,192.168.0.0/16", "DST-PORT,443"}}
	g := geoBuilder{}
	packed, err := g.packClassical(&s)
	if err != nil || packed || len(g.sites) != 0 || len(g.ips) != 0 {
		t.Fatal("source IP or port conditions must not become destination IP DAT")
	}
	expr, err := expressions("RULE-SET", "mixed", map[string]compiledSet{"mixed": s})
	if err != nil || len(expr) != 3 || expr[1] != `sip("192.168.0.0/16")` || expr[2] != "dport(443)" {
		t.Fatalf("inline conditions changed: %v %v", expr, err)
	}
}

func TestClassicalHTTPRefreshNativeDATAndRulePriority(t *testing.T) {
	var payload atomic.Value
	payload.Store("DOMAIN-SUFFIX,example.org\nDOMAIN-KEYWORD,sharepoint\nIP-CIDR,10.0.0.0/8\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, payload.Load().(string)) }))
	defer server.Close()
	m, _ := setup(t)
	if dae := os.Getenv("DAE_TEST_BINARY"); dae != "" {
		m.S.Dae = dae
	}
	c := fixture()
	c["rule-providers"] = M{"custom": M{"type": "http", "behavior": "classical", "format": "text", "url": server.URL}}
	c["rules"] = []any{"DOMAIN,before.example,DIRECT", "RULE-SET,custom,默认", "DOMAIN,after.example,DIRECT", "MATCH,DIRECT"}
	source, _ := yaml.Marshal(c)
	first, r, err := m.build(context.Background(), false, true, source, nil, m.settings())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rules) != 5 || r.Rules[0].Source != "DOMAIN,before.example,DIRECT" || r.Rules[1].Target != "默认" || r.Rules[2].Target != "默认" || r.Rules[3].Source != "DOMAIN,after.example,DIRECT" {
		t.Fatalf("rule priority changed: %+v", r.Rules)
	}
	if err = m.activate(context.Background(), first, false); err != nil {
		t.Fatal(err)
	}
	read := func(rev string) []byte {
		b, e := os.ReadFile(filepath.Join(m.Root, "revisions", rev, "rules-site.dat"))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	before := read(first)
	payload.Store("DOMAIN-SUFFIX,changed.example\nIP-CIDR,10.0.0.0/8\n")
	cached, _, err := m.build(context.Background(), false, false, nil, nil, m.settings())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, read(cached)) {
		t.Fatal("cached build fetched unexpected content")
	}
	fresh, r, err := m.build(context.Background(), false, true, nil, nil, m.settings())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, read(fresh)) || r.Validation != "passed" {
		t.Fatal("HTTP refresh did not regenerate a validated DAT")
	}
	payload.Store("UNKNOWN-CONDITION,example.org\n")
	if _, _, err = m.build(context.Background(), false, true, nil, nil, m.settings()); err == nil {
		t.Fatal("unsupported online rule silently dropped")
	}
	if m.currentID() != first {
		t.Fatal("failed online rule replaced active revision")
	}
}

func TestEnablingRuleSyncFetchesBeforeApplying(t *testing.T) {
	var payload atomic.Value
	payload.Store("DOMAIN-SUFFIX,old.example\n")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, payload.Load().(string))
	}))
	defer server.Close()
	m, token := setup(t)
	c := fixture()
	c["rule-providers"] = M{"custom": M{"type": "http", "behavior": "classical", "format": "text", "url": server.URL}}
	c["rules"] = []any{"RULE-SET,custom,默认", "MATCH,DIRECT"}
	source, _ := yaml.Marshal(c)
	first, _, err := m.build(context.Background(), false, true, source, nil, m.settings())
	if err != nil {
		t.Fatal(err)
	}
	if err = m.activate(context.Background(), first, false); err != nil {
		t.Fatal(err)
	}
	payload.Store("DOMAIN-SUFFIX,new.example\n")
	s := m.settings()
	body, _ := json.Marshal(M{"lan": s.LAN, "wan": s.WAN, "log_level": s.LogLevel, "update_time": s.UpdateTime, "timezone": s.Timezone, "auto_update": s.AutoUpdate, "refresh_rules": true})
	a := &api{m: m, sessions: map[string]session{}, attempts: map[string]attempt{}}
	req := httptest.NewRequest("PUT", "/api/settings", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-DAE-Request", "1")
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("settings failed: %d %s", w.Code, w.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.RLock()
		j := m.job
		m.mu.RUnlock()
		if j.State != "running" {
			if j.State != "success" {
				t.Fatal(j.Message)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("settings job timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
	data, _ := os.ReadFile(filepath.Join(m.currentDir(), "rules-site.dat"))
	if !m.settings().RefreshRules || requests.Load() != 2 || !bytes.Contains(data, []byte("new.example")) || bytes.Contains(data, []byte("old.example")) {
		t.Fatal("enabling rule sync did not fetch and apply current upstream data")
	}
}
