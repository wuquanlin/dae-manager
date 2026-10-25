package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func subscriptionFixture(t *testing.T, m *Manager, url string) {
	t.Helper()
	c := fixture()
	c["proxies"] = []any{}
	c["proxy-providers"] = M{"Airport1": M{"type": "http", "url": url, "header": M{"User-Agent": []any{"custom-agent"}}, "override": M{"tfo": true}}}
	b, _ := yaml.Marshal(c)
	if e := atomicWrite(filepath.Join(m.Root, "source.yaml"), b, 0600); e != nil {
		t.Fatal(e)
	}
}
func subHash(t *testing.T, m *Manager) string {
	t.Helper()
	v, e := m.subscriptions()
	if e != nil {
		t.Fatal(e)
	}
	return v["source_hash"].(string)
}
func TestSubscriptionSaveOnlyIsPendingAndVersioned(t *testing.T) {
	m, _ := setup(t)
	subscriptionFixture(t, m, "https://old.example/subscription?token=old-secret")
	original, _ := os.ReadFile(filepath.Join(m.Root, "source.yaml"))
	hash := subHash(t, m)
	if e := m.saveSubscriptions([]SubscriptionLink{{"Airport1", "https://new.example/feed?token=new-secret"}}, hash); e != nil {
		t.Fatal(e)
	}
	active, _ := os.ReadFile(filepath.Join(m.Root, "source.yaml"))
	if string(active) != string(original) || m.currentID() != "" {
		t.Fatal("save applied pending subscription")
	}
	candidate, e := m.subscriptionSource()
	if e != nil || !strings.Contains(string(candidate), "new-secret") {
		t.Fatal("next pull does not use pending URL", e)
	}
	before, _ := parseYAML(original)
	after, _ := parseYAML(candidate)
	obj(obj(before["proxy-providers"])["Airport1"])["url"] = "https://new.example/feed?token=new-secret"
	if !reflect.DeepEqual(before, after) {
		t.Fatal("non-URL fields changed")
	}
	if e = m.saveSubscriptions([]SubscriptionLink{{"Airport1", "https://other.example/feed"}}, hash); e == nil {
		t.Fatal("stale form overwrote pending link")
	}
	if e = m.saveSubscriptions([]SubscriptionLink{{"Airport1", "file:///etc/passwd"}}, subHash(t, m)); e == nil {
		t.Fatal("file subscription accepted")
	}
	audit := tail(filepath.Join(m.Root, "audit.log"), 1<<20)
	if strings.Contains(audit, "old-secret") || strings.Contains(audit, "new-secret") {
		t.Fatal("subscription URL leaked to audit")
	}
	if e = m.saveSubscriptions([]SubscriptionLink{{"Airport1", "https://old.example/subscription?token=old-secret"}}, subHash(t, m)); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(m.Root, "subscription-draft.json")); !os.IsNotExist(e) {
		t.Fatal("restoring active URL did not clear draft")
	}
}
func TestPatchSubscriptionPreservesYAMLCommentsAndMerge(t *testing.T) {
	source := []byte("# source comment\ntemplate: &base\n  type: http\n  header: {User-Agent: [agent]}\nproxy-providers:\n  First:\n    <<: *base\n    url: 'https://old.example/one' # keep comment\n    filter: HK\n  Second:\n    <<: *base\n    url: https://old.example/two\ndns: {ipv6: false}\n")
	got, e := patchSubscriptionURLs(source, map[string]string{"First": "https://new.example/one?token=abc"})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(got), "# source comment") || !strings.Contains(string(got), "# keep comment") {
		t.Fatal("comments lost")
	}
	c, _ := parseYAML(got)
	if str(obj(obj(c["proxy-providers"])["Second"])["url"]) != "https://old.example/two" {
		t.Fatal("second provider changed")
	}
}
func TestSubscriptionPullReportsChangesAndPersistsResult(t *testing.T) {
	m, _ := setup(t)
	makeNode := func(name string, port int) M {
		n := obj(seq(fixture()["proxies"])[0])
		n["name"] = name
		n["port"] = port
		return n
	}
	server := func(nodes []any) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := yaml.Marshal(M{"proxies": nodes})
			_, _ = w.Write(b)
		}))
	}
	old := server([]any{makeNode("香港 A", 443), makeNode("香港 B", 443)})
	defer old.Close()
	fresh := server([]any{makeNode("香港 A", 8443), makeNode("香港 C", 443)})
	defer fresh.Close()
	subscriptionFixture(t, m, old.URL)
	rev := buildFixture(t, m)
	if e := m.activate(context.Background(), rev, false); e != nil {
		t.Fatal(e)
	}
	var selections map[string]string
	_ = readJSON(filepath.Join(m.Root, "selections.json"), &selections)
	if e := m.saveSubscriptions([]SubscriptionLink{{"Airport1", fresh.URL}}, subHash(t, m)); e != nil {
		t.Fatal(e)
	}
	if e := m.update(context.Background(), false); e != nil {
		t.Fatal(e)
	}
	result, e := m.lastSync()
	if e != nil || result.State != "success" || !result.Applied || !result.NodesComplete || result.Added != 1 || result.Updated != 1 || len(result.Removed) != 1 || result.Validation != "passed" {
		t.Fatalf("wrong update diff: %+v %v", result, e)
	}
	var current map[string]string
	_ = readJSON(filepath.Join(m.Root, "selections.json"), &current)
	if !reflect.DeepEqual(current, selections) {
		t.Fatal("manual selection reset")
	}
	b, _ := os.ReadFile(filepath.Join(m.Root, "source.yaml"))
	c, _ := parseYAML(b)
	if str(obj(obj(c["proxy-providers"])["Airport1"])["url"]) != fresh.URL {
		t.Fatal("new URL not committed")
	}
	if _, e = os.Stat(filepath.Join(m.Root, "subscription-draft.json")); !os.IsNotExist(e) {
		t.Fatal("applied draft not cleared")
	}
	reopened, e := openManager(m.Root)
	if e != nil {
		t.Fatal(e)
	}
	persisted, e := reopened.lastSync()
	if e != nil || persisted.State != "success" || len(persisted.Nodes) != 2 {
		t.Fatal("result lost after manager restart", e)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "vless://") || strings.Contains(string(encoded), "00000000-0000-4000") {
		t.Fatal("result leaks node credentials")
	}
}
func TestSubscriptionPullFailurePreservesActiveAndDraft(t *testing.T) {
	m, _ := setup(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := yaml.Marshal(M{"proxies": fixture()["proxies"]})
		_, _ = w.Write(b)
	}))
	defer server.Close()
	subscriptionFixture(t, m, server.URL)
	rev := buildFixture(t, m)
	_ = m.activate(context.Background(), rev, false)
	before, _ := os.ReadFile(filepath.Join(m.Root, "source.yaml"))
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer broken.Close()
	if e := m.saveSubscriptions([]SubscriptionLink{{"Airport1", broken.URL + "?token=never-show"}}, subHash(t, m)); e != nil {
		t.Fatal(e)
	}
	e := m.update(context.Background(), false)
	if e == nil {
		t.Fatal("failed download accepted")
	}
	after, _ := os.ReadFile(filepath.Join(m.Root, "source.yaml"))
	if m.currentID() != rev || string(after) != string(before) {
		t.Fatal("failed pull changed active source/config")
	}
	result, e := m.lastSync()
	if e != nil || result.State != "failed" || result.Applied || result.NodesComplete || result.Error == "" {
		t.Fatalf("failed result wrong: %+v", result)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "never-show") {
		t.Fatal("URL token leaked")
	}
	if _, e = os.Stat(filepath.Join(m.Root, "subscription-draft.json")); e != nil {
		t.Fatal("failed pull discarded pending edit")
	}
}
func TestSubscriptionValidationFailureShowsFetchedNodes(t *testing.T) {
	m, _ := setup(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := yaml.Marshal(M{"proxies": fixture()["proxies"]})
		_, _ = w.Write(b)
	}))
	defer server.Close()
	subscriptionFixture(t, m, server.URL)
	rev := buildFixture(t, m)
	_ = m.activate(context.Background(), rev, false)
	m.S.Dae = "/bin/false"
	if e := m.update(context.Background(), false); e == nil {
		t.Fatal("bad native validation applied")
	}
	r, e := m.lastSync()
	if e != nil || r.State != "failed" || !r.NodesComplete || len(r.Nodes) != 1 || r.Validation != "failed" || m.currentID() != rev {
		t.Fatalf("validation error lost fetched nodes: %+v %v", r, e)
	}
}
func TestSubscriptionSourceConflictAndAPIAccess(t *testing.T) {
	m, token := setup(t)
	subscriptionFixture(t, m, "https://old.example/feed")
	_ = m.saveSubscriptions([]SubscriptionLink{{"Airport1", "https://new.example/feed"}}, subHash(t, m))
	subscriptionFixture(t, m, "https://external.example/feed")
	if _, e := m.subscriptionSource(); e == nil {
		t.Fatal("pending draft overwrote external URL change")
	}
	a := &api{m: m, sessions: map[string]session{}, attempts: map[string]attempt{}}
	for _, path := range []string{"/api/subscriptions", "/api/update/result"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, req)
		if w.Code != 401 {
			t.Fatal("private subscription/result accessible without auth")
		}
	}
	req := httptest.NewRequest("PUT", "/api/subscriptions", strings.NewReader(fmt.Sprintf(`{"items":[{"name":"Airport1","url":"https://ok.example/sub"}],"source_hash":%q,"pull":false}`, subHash(t, m))))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("subscription mutation missing CSRF marker allowed")
	}
}

func TestSubscriptionSaveAPIAndDisappearingSelection(t *testing.T) {
	m, token := setup(t)
	node := obj(seq(fixture()["proxies"])[0])
	serve := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := M{}
			for k, x := range node {
				v[k] = x
			}
			v["name"] = name
			b, _ := yaml.Marshal(M{"proxies": []any{v}})
			_, _ = w.Write(b)
		}))
	}
	old := serve("香港 A")
	defer old.Close()
	fresh := serve("香港 C")
	defer fresh.Close()
	subscriptionFixture(t, m, old.URL)
	// Select the node itself, rather than an automatic subgroup.
	source, _ := os.ReadFile(filepath.Join(m.Root, "source.yaml"))
	c, _ := parseYAML(source)
	groups := seq(c["proxy-groups"])
	obj(groups[1])["proxies"] = []any{"自动", "香港 A", "DIRECT"}
	source, _ = yaml.Marshal(c)
	_ = atomicWrite(filepath.Join(m.Root, "source.yaml"), source, 0600)
	rev, _, e := m.build(context.Background(), true, false, nil, map[string]string{"默认": "香港 A"}, m.settings())
	if e != nil {
		t.Fatal(e)
	}
	_ = m.activate(context.Background(), rev, false)
	a := &api{m: m, sessions: map[string]session{}, attempts: map[string]attempt{}}
	body, _ := json.Marshal(M{"items": []SubscriptionLink{{"Airport1", fresh.URL}}, "source_hash": subHash(t, m), "pull": true, "rules": false})
	req := httptest.NewRequest("PUT", "/api/subscriptions", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-DAE-Request", "1")
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, req)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	job := awaitJob(t, m)
	if job.State != "failed" || m.currentID() != rev {
		t.Fatal("missing manual selection silently replaced")
	}
	result, e := m.lastSync()
	if e != nil || result.JobID != job.ID || !result.NodesComplete || len(result.Nodes) != 1 || len(result.Removed) != 1 || result.Applied {
		t.Fatalf("missing-selection result wrong: %+v %v", result, e)
	}
}

func TestSyncDiffUsesSubscriptionFingerprintBeforeNativeOverride(t *testing.T) {
	before := []Node{{Name: "node", ID: "n_1", Type: "vless", Provider: "source", Fingerprint: "source-value"}}
	after := []Node{{Name: "node", ID: "n_1", Type: "vless", Provider: "source", Fingerprint: "source-value"}}
	nodes, _, _, updated, unchanged, _ := syncNodes(before, after, true, map[string]string{"n_1": "manual-native-override"})
	if len(nodes) != 1 || nodes[0].Change != "unchanged" || updated != 0 || unchanged != 1 {
		t.Fatal("native overlay mislabeled as subscription update")
	}
}
