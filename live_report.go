package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// Reconcile display metadata with the actual native configuration. URI secrets
// never leave this boundary. Generated virtual selectors remain UI controls.
func (m *Manager) liveReport(ctx context.Context) (Report, error) {
	r, e := m.report()
	if e != nil {
		return r, e
	}
	inv, e := m.inventory(ctx)
	if e != nil {
		r.note("warning", "原生配置清单", "dae-helper 不可用，当前仅展示最近转换元数据；请修复组件后刷新")
		return r, nil
	}
	names := displayNames(r)
	oldNodes := map[string]Node{}
	for _, n := range r.Nodes {
		oldNodes[n.ID] = n
	}
	r.Nodes = nil
	for _, n := range inv.Nodes {
		v, ok := oldNodes[n.ID]
		if !ok {
			v = Node{Name: n.ID, ID: n.ID, Type: n.Type, Provider: "原生 dae"}
		}
		v.URI = ""
		r.Nodes = append(r.Nodes, v)
	}
	native := map[string]NativeGroup{}
	for _, g := range inv.Groups {
		native[g.ID] = g
	}
	var groups []Group
	for _, g := range r.Groups {
		if g.Type == "select" {
			groups = append(groups, g)
			continue
		}
		ng, ok := native[g.ID]
		if !ok {
			continue
		}
		g.Members = nil
		for _, id := range ng.Members {
			if name := names[id]; name != "" {
				g.Members = append(g.Members, name)
			} else {
				g.Members = append(g.Members, id)
			}
		}
		g.Policy = ng.Policy
		if !ng.Known {
			g.Members = nil
			r.note("warning", g.Name, "存在高级节点过滤条件，面板无法完整展开成员；以 dae 实际运行结果为准")
		}
		groups = append(groups, g)
		delete(native, g.ID)
	}
	for _, g := range inv.Groups {
		if strings.HasPrefix(g.ID, "solo_") {
			continue
		}
		if _, ok := native[g.ID]; !ok {
			continue
		}
		v := Group{Name: g.ID, ID: g.ID, Type: "native", Policy: g.Policy}
		for _, id := range g.Members {
			if name := names[id]; name != "" {
				v.Members = append(v.Members, name)
			} else {
				v.Members = append(v.Members, id)
			}
		}
		groups = append(groups, v)
		if !g.Known {
			r.note("warning", g.ID, "存在高级节点过滤条件，面板无法完整展开成员；以 dae 实际运行结果为准")
		}
	}
	r.Groups = groups
	// Manual configurations may change routing independently of the Mihomo input.
	// Only replace the original metadata when the native config has an overlay.
	base, _ := os.ReadFile(filepath.Join(m.currentDir(), "baseline-config.dae"))
	current, _ := os.ReadFile(filepath.Join(m.currentDir(), "config.dae"))
	if len(base) > 0 && string(base) != string(current) {
		r.Rules = nil
		for _, rule := range inv.Rules {
			r.Rules = append(r.Rules, Rule{Source: "运行 dae 配置", Expr: rule.Expression, Target: rule.Outbound, Resolved: rule.Outbound})
		}
	}
	if inv.Includes {
		r.note("warning", "include", "当前配置含 include；面板仅展开主文件内的节点、规则和策略。原生校验仍检查引用文件")
	}
	return r, nil
}
