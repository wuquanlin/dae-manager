package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type SubscriptionLink struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}
type SubscriptionDraft struct {
	Base  map[string]string `json:"base"`
	Links map[string]string `json:"links"`
	Saved time.Time         `json:"saved"`
}
type SubscriptionView struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	ActiveURL string `json:"active_url"`
	Host      string `json:"host"`
	Count     int    `json:"count"`
	Pending   bool   `json:"pending"`
	Conflict  bool   `json:"conflict"`
}

func validSubscriptionURL(raw string) bool {
	if len(raw) > 8192 || strings.ContainsAny(raw, "\r\n\x00") {
		return false
	}
	u, e := url.Parse(raw)
	return e == nil && u.Hostname() != "" && in(u.Scheme, []string{"http", "https"})
}
func (m *Manager) subscriptions() (M, error) {
	b, e := os.ReadFile(filepath.Join(m.Root, "source.yaml"))
	if e != nil {
		return nil, fmt.Errorf("尚无订阅源配置")
	}
	source, e := parseYAML(b)
	if e != nil {
		return nil, fmt.Errorf("订阅源配置格式错误")
	}
	var pending SubscriptionDraft
	pendingRaw, e := os.ReadFile(filepath.Join(m.Root, "subscription-draft.json"))
	if e != nil && !os.IsNotExist(e) {
		return nil, fmt.Errorf("待应用订阅记录读取失败")
	}
	if len(pendingRaw) > 0 && json.Unmarshal(pendingRaw, &pending) != nil {
		return nil, fmt.Errorf("待应用订阅记录格式错误")
	}
	report, _ := m.report()
	counts := map[string]int{}
	for _, n := range report.Nodes {
		counts[n.Provider]++
	}
	items := []SubscriptionView{}
	providers := obj(source["proxy-providers"])
	for _, name := range keys(providers) {
		p := obj(providers[name])
		if str(p["type"]) != "http" {
			continue
		}
		active := str(p["url"])
		link := active
		if v, ok := pending.Links[name]; ok {
			link = v
		}
		host := ""
		if u, e := url.Parse(link); e == nil {
			host = u.Host
		}
		items = append(items, SubscriptionView{Name: name, URL: link, ActiveURL: active, Host: host, Count: counts[name], Pending: link != active, Conflict: pending.Links[name] != "" && pending.Base[name] != active && link != active})
	}
	return M{"items": items, "source_hash": subscriptionStateHash(b, pendingRaw), "saved_at": pending.Saved, "note": "保存链接仅保留待应用修改；拉取成功并通过校验后才替换生效配置。每日更新也会使用已保存的待应用链接。"}, nil
}
func (m *Manager) saveSubscriptions(items []SubscriptionLink, baseHash string) error {
	b, e := os.ReadFile(filepath.Join(m.Root, "source.yaml"))
	if e != nil {
		return fmt.Errorf("尚无订阅源配置")
	}
	pendingRaw, e := os.ReadFile(filepath.Join(m.Root, "subscription-draft.json"))
	if e != nil && !os.IsNotExist(e) {
		return fmt.Errorf("待应用订阅记录读取失败")
	}
	if baseHash == "" || baseHash != subscriptionStateHash(b, pendingRaw) {
		return fmt.Errorf("源配置已变化，请刷新订阅管理后重新保存")
	}
	c, e := parseYAML(b)
	if e != nil {
		return fmt.Errorf("订阅源配置格式错误")
	}
	providers := obj(c["proxy-providers"])
	if len(items) > 64 {
		return fmt.Errorf("单次最多修改 64 个订阅")
	}
	draft := SubscriptionDraft{Base: map[string]string{}, Links: map[string]string{}, Saved: time.Now()}
	seen := map[string]bool{}
	// A complete form prevents an old/partial client from silently dropping a
	// pending edit for another provider.
	expected := 0
	for _, v := range providers {
		if str(obj(v)["type"]) == "http" {
			expected++
		}
	}
	if len(items) != expected {
		return fmt.Errorf("订阅列表不完整，请刷新后重新保存")
	}
	for _, item := range items {
		p := obj(providers[item.Name])
		if seen[item.Name] || str(p["type"]) != "http" {
			return fmt.Errorf("订阅名称无效或重复")
		}
		seen[item.Name] = true
		raw := strings.TrimSpace(item.URL)
		if !validSubscriptionURL(raw) {
			return fmt.Errorf("订阅「%s」必须使用有效 HTTP(S) 链接", item.Name)
		}
		if raw != str(p["url"]) {
			draft.Base[item.Name] = str(p["url"])
			draft.Links[item.Name] = raw
		}
	}
	if len(draft.Links) == 0 {
		if e = os.Remove(filepath.Join(m.Root, "subscription-draft.json")); e != nil && !os.IsNotExist(e) {
			return e
		}
		return nil
	}
	if _, e = patchSubscriptionURLs(b, draft.Links); e != nil {
		return e
	}
	if e = writeJSON(filepath.Join(m.Root, "subscription-draft.json"), draft); e != nil {
		return e
	}
	m.audit("subscriptions_saved", fmt.Sprintf("保存 %d 个待应用订阅链接；链接不写入日志", len(draft.Links)))
	return nil
}

func mapNodeValue(n *yaml.Node, key string, depth int) *yaml.Node {
	if n == nil || depth > 32 {
		return nil
	}
	if n.Kind == yaml.AliasNode {
		return mapNodeValue(n.Alias, key, depth+1)
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value != "<<" {
			continue
		}
		merge := n.Content[i+1]
		if merge.Kind == yaml.SequenceNode {
			for _, child := range merge.Content {
				if v := mapNodeValue(child, key, depth+1); v != nil {
					return v
				}
			}
		} else if v := mapNodeValue(merge, key, depth+1); v != nil {
			return v
		}
	}
	return nil
}
func copyMapNode(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	v := *n
	v.Content = append([]*yaml.Node{}, n.Content...)
	return &v
}
func setMapNode(n *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content[i+1] = value
			return
		}
	}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
}
func patchSubscriptionURLs(source []byte, links map[string]string) ([]byte, error) {
	expected, e := parseYAML(source)
	if e != nil {
		return nil, fmt.Errorf("订阅源配置格式错误")
	}
	var doc yaml.Node
	if yaml.Unmarshal(source, &doc) != nil || len(doc.Content) != 1 {
		return nil, fmt.Errorf("无法读取订阅源 YAML")
	}
	root := doc.Content[0]
	providers := copyMapNode(mapNodeValue(root, "proxy-providers", 0))
	if providers == nil {
		return nil, fmt.Errorf("没有可修改的订阅")
	}
	for name, raw := range links {
		p := obj(obj(expected["proxy-providers"])[name])
		if str(p["type"]) != "http" || !validSubscriptionURL(raw) {
			return nil, fmt.Errorf("订阅列表或链接无效")
		}
		provider := copyMapNode(mapNodeValue(providers, name, 0))
		if provider == nil {
			return nil, fmt.Errorf("订阅结构不支持编辑")
		}
		value := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: raw, Style: yaml.DoubleQuotedStyle}
		if old := mapNodeValue(provider, "url", 0); old != nil {
			value.HeadComment = old.HeadComment
			value.LineComment = old.LineComment
			value.FootComment = old.FootComment
		}
		setMapNode(provider, "url", value)
		setMapNode(providers, name, provider)
		p["url"] = raw
		obj(expected["proxy-providers"])[name] = p
	}
	setMapNode(root, "proxy-providers", providers)
	out, e := yaml.Marshal(&doc)
	if e != nil {
		return nil, fmt.Errorf("保存订阅 YAML 失败")
	}
	actual, e := parseYAML(out)
	if e != nil || !reflect.DeepEqual(expected, actual) {
		return nil, fmt.Errorf("源配置的 YAML 锚点结构无法安全修改；原配置保持不变")
	}
	return out, nil
}
func (m *Manager) subscriptionSource() ([]byte, error) {
	b, e := os.ReadFile(filepath.Join(m.Root, "source.yaml"))
	if e != nil {
		return nil, e
	}
	var pending SubscriptionDraft
	if e = readJSON(filepath.Join(m.Root, "subscription-draft.json"), &pending); os.IsNotExist(e) {
		return b, nil
	} else if e != nil {
		return nil, fmt.Errorf("待应用订阅记录读取失败")
	}
	c, e := parseYAML(b)
	if e != nil {
		return nil, fmt.Errorf("源配置格式错误")
	}
	for name, raw := range pending.Links {
		p := obj(obj(c["proxy-providers"])[name])
		if str(p["type"]) != "http" || str(p["url"]) != pending.Base[name] && str(p["url"]) != raw {
			return nil, fmt.Errorf("订阅「%s」已发生变化，请刷新订阅管理并重新保存链接", name)
		}
	}
	if len(pending.Links) == 0 {
		return b, nil
	}
	return patchSubscriptionURLs(b, pending.Links)
}
func (m *Manager) clearAppliedSubscriptions() {
	b, e := os.ReadFile(filepath.Join(m.Root, "source.yaml"))
	if e != nil {
		return
	}
	c, e := parseYAML(b)
	if e != nil {
		return
	}
	var draft SubscriptionDraft
	if readJSON(filepath.Join(m.Root, "subscription-draft.json"), &draft) != nil {
		return
	}
	for name, raw := range draft.Links {
		if str(obj(obj(c["proxy-providers"])[name])["url"]) != raw {
			return
		}
	}
	_ = os.Remove(filepath.Join(m.Root, "subscription-draft.json"))
}

func subscriptionStateHash(source, pending []byte) string {
	if len(pending) == 0 {
		return digest(source)
	}
	joined := append(append([]byte{}, source...), 0)
	joined = append(joined, pending...)
	return digest(joined)
}
