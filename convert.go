package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/dlclark/regexp2"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Converter struct {
	Settings     Settings
	Cache        string
	Geodata      string
	Selections   map[string]string
	RefreshNodes bool
	RefreshRules bool
	Progress     func(string, string, Report)
}

func (cv Converter) progress(stage, message string, report Report) {
	if cv.Progress != nil {
		cv.Progress(stage, message, report)
	}
}

func match(pattern, name string) (bool, error) {
	if pattern == "" {
		return true, nil
	}
	r, e := regexp2.Compile(pattern, regexp2.RE2)
	if e != nil {
		return false, fmt.Errorf("分组正则语法无效")
	}
	r.MatchTimeout = 100 * time.Millisecond
	return r.MatchString(name)
}
func (cv Converter) Convert(ctx context.Context, source []byte, stage string) (Report, error) {
	r := Report{Created: time.Now(), Validation: "pending", Nodes: []Node{}, Groups: []Group{}, Rules: []Rule{}, Providers: []ProviderInfo{}, Notices: []Notice{}}
	c, e := parseYAML(source)
	if e != nil {
		return r, fmt.Errorf("Mihomo YAML 语法错误")
	}
	if e = cv.Settings.validate(); e != nil {
		return r, e
	}
	if str(c["mode"]) != "" && str(c["mode"]) != "rule" {
		return r, fmt.Errorf("当前仅转换 rule 模式，避免误改全局/直连语义")
	}
	if e = os.MkdirAll(stage, 0700); e != nil {
		return r, e
	}
	if e = os.MkdirAll(cv.Cache, 0700); e != nil {
		return r, e
	}
	seen := map[string]string{}
	addNode := func(n M, provider string) error {
		uri, err := nodeURI(n, &r)
		if err != nil {
			r.note("error", str(n["name"]), err.Error())
			if cv.Settings.Strict {
				return err
			}
			return nil
		}
		name := str(n["name"])
		if old, ok := seen[name]; ok {
			if old != uri {
				return fmt.Errorf("不同节点重名 %s，请先改名", name)
			}
			return nil
		}
		seen[name] = uri
		r.Nodes = append(r.Nodes, Node{Name: name, ID: id("n_", name), Type: str(n["type"]), Provider: provider, URI: uri, Fingerprint: digest([]byte(uri))})
		return nil
	}
	for _, raw := range seq(c["proxies"]) {
		if e = addNode(obj(raw), "inline"); e != nil {
			return r, e
		}
	}
	for _, name := range keys(obj(c["proxy-providers"])) {
		p := obj(obj(c["proxy-providers"])[name])
		cv.progress("nodes", "正在读取订阅「"+name+"」", r)
		var nodes []any
		if str(p["type"]) == "inline" {
			nodes = seq(p["payload"])
		} else {
			if str(p["type"]) != "http" {
				return r, fmt.Errorf("节点源 %s：仅支持 http/inline，不读取任意本地路径", name)
			}
			b, err := cachedFetch(ctx, cv.Cache, p, cv.RefreshNodes)
			if err != nil {
				return r, fmt.Errorf("节点源 %s：%w", name, err)
			}
			doc, err := parseYAML(b)
			if err != nil || len(seq(doc["proxies"])) == 0 {
				// URI subscriptions are converted into synthetic nodes without exposing credentials.
				if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b))); err == nil {
					b = decoded
				}
				for _, line := range strings.Split(string(b), "\n") {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					n, err := uriNode(line, name)
					if err != nil {
						return r, fmt.Errorf("节点源 %s 不是有效 Mihomo YAML 或 URI 订阅", name)
					}
					if _, ok := seen[n.Name]; ok {
						return r, fmt.Errorf("订阅节点重名")
					}
					seen[n.Name] = line
					r.Nodes = append(r.Nodes, n)
				}
			} else {
				nodes = seq(doc["proxies"])
			}
		}
		before := len(r.Nodes)
		for _, raw := range nodes {
			n := obj(raw)
			for k, v := range obj(p["override"]) {
				if k != "additional-prefix" && k != "additional-suffix" {
					n[k] = v
				}
			}
			ov := obj(p["override"])
			n["name"] = str(ov["additional-prefix"]) + str(n["name"]) + str(ov["additional-suffix"])
			ok, err := match(str(p["filter"]), str(n["name"]))
			if err != nil {
				return r, err
			}
			excluded := false
			if str(p["exclude-filter"]) != "" {
				excluded, err = match(str(p["exclude-filter"]), str(n["name"]))
				if err != nil {
					return r, err
				}
			}
			if !ok || excluded {
				continue
			}
			if err = addNode(n, name); err != nil {
				return r, err
			}
		}
		count := len(r.Nodes) - before
		if count == 0 && len(nodes) > 0 {
			return r, fmt.Errorf("节点源 %s 过滤后为空", name)
		}
		for _, n := range r.Nodes {
			if n.Provider == name && len(nodes) == 0 {
				count++
			}
		}
		if count == 0 {
			return r, fmt.Errorf("节点源 %s 为空", name)
		}
		r.Providers = append(r.Providers, ProviderInfo{Name: name, Kind: "nodes", Count: count})
		cv.progress("nodes", fmt.Sprintf("订阅「%s」已读取 %d 个节点", name, count), r)
	}
	if len(r.Nodes) == 0 {
		return r, fmt.Errorf("没有可用节点，拒绝生成空订阅配置")
	}
	cv.progress("groups", "节点已读取，正在转换策略组", r)
	if e = makeGroups(c, &r, cv.Selections); e != nil {
		return r, e
	}
	cv.progress("rules", "正在转换分流规则与规则集", r)
	sets := map[string]compiledSet{}
	gb := geoBuilder{}
	// Only referenced sets are fetched; preserve source rules instead of mapping by similar names.
	needed := map[string]bool{}
	for _, line := range strs(c["rules"]) {
		p := strings.Split(line, ",")
		if len(p) > 1 && p[0] == "RULE-SET" {
			needed[p[1]] = true
		}
	}
	for k := range obj(obj(c["dns"])["nameserver-policy"]) {
		if strings.HasPrefix(k, "rule-set:") {
			for _, name := range strings.Split(strings.TrimPrefix(k, "rule-set:"), ",") {
				needed[name] = true
			}
		}
	}
	names := make([]string, 0, len(needed))
	for n := range needed {
		names = append(names, n)
	}
	sortStrings(names)
	for _, name := range names {
		p, ok := obj(c["rule-providers"])[name]
		if !ok {
			return r, fmt.Errorf("规则源 %s 未定义", name)
		}
		set, info, err := loadRuleSet(ctx, name, obj(p), cv.Cache, stage, cv.Settings.Mihomo, cv.RefreshRules)
		if err != nil {
			return r, err
		}
		r.Providers = append(r.Providers, info)
		if set.Behavior == "classical" {
			packed, err := gb.packClassical(&set)
			if err != nil {
				return r, fmt.Errorf("规则源 %s：%w", name, err)
			}
			if packed {
				r.note("info", name, fmt.Sprintf("已将 %d 条域名条件和 %d 条目标 IP 条件打包为 DAT；保留原规则集优先级和出口，更新时重新生成。", set.PackedDomains, set.PackedIPs))
			}
		} else {
			if err = gb.add(set.ID, set.Behavior, set.Lines); err != nil {
				return r, fmt.Errorf("规则源 %s：%w", name, err)
			}
		}
		sets[name] = set
	}
	for file, b := range map[string][]byte{"rules-site.dat": gb.sites, "rules-ip.dat": gb.ips} {
		blob := filepath.Join(cv.Cache, "dat-"+digest(b))
		if _, err := os.Stat(blob); os.IsNotExist(err) {
			if e = atomicWrite(blob, b, 0600); e != nil {
				return r, e
			}
		}
		if e = linkOrCopy(blob, filepath.Join(stage, file)); e != nil {
			return r, e
		}
	}
	for _, file := range []string{"geoip.dat", "geosite.dat"} {
		b, err := os.ReadFile(filepath.Join(cv.Geodata, file))
		if err != nil {
			return r, fmt.Errorf("缺少 %s，请先安装 geodata", file)
		}
		_ = b
		if e = linkOrCopy(filepath.Join(cv.Geodata, file), filepath.Join(stage, file)); e != nil {
			return r, e
		}
	}
	foundMatch := false
	for _, line := range strs(c["rules"]) {
		p := strings.Split(line, ",")
		if len(p) < 2 {
			return r, fmt.Errorf("规则格式无效")
		}
		if foundMatch {
			return r, fmt.Errorf("MATCH 后仍有规则，拒绝改变不可达规则语义")
		}
		target := ""
		exprs := []string{}
		if p[0] == "MATCH" {
			target = p[1]
			exprs = []string{"fallback"}
			foundMatch = true
		} else {
			if len(p) < 3 {
				return r, fmt.Errorf("规则缺少目标")
			}
			target = p[2]
			exprs, e = expressions(p[0], p[1], sets)
			if e != nil {
				return r, fmt.Errorf("规则 %s：%w", p[0], e)
			}
		}
		resolved, err := resolveTarget(target, r.Groups, r.Nodes, map[string]bool{})
		if err != nil {
			return r, err
		}
		for _, expr := range exprs {
			r.Rules = append(r.Rules, Rule{line, expr, target, resolved})
		}
	}
	if !foundMatch {
		r.note("warning", "MATCH", "原配置没有 MATCH，使用 direct 作为最终出口。 ")
		r.Rules = append(r.Rules, Rule{Source: "MATCH,DIRECT", Expr: "fallback", Target: "DIRECT", Resolved: "direct"})
	}
	cfg, e := render(c, r, sets, cv.Settings)
	if e != nil {
		return r, e
	}
	r.ConfigHash = digest([]byte(cfg))
	if e = atomicWrite(filepath.Join(stage, "config.dae"), []byte(cfg), 0600); e != nil {
		return r, e
	}
	if e = writeJSON(filepath.Join(stage, "hosts.json"), obj(c["hosts"])); e != nil {
		return r, e
	}
	for _, n := range []Notice{
		{"warning", "节点域名解析", "proxy-server-nameserver / default-nameserver 未等价迁移到逐节点 DNS；dae 使用系统解析及自身回退解析。请保证安装时系统 DNS 可用。"},
		{"info", "no-resolve", "IP 规则保留目标地址匹配；Mihomo 的 no-resolve 标记不直接迁移，DNS 映射及分流行为以 dae 为准。"},
		{"info", "TUN / 端口", "Mihomo TUN、HTTP/SOCKS/mixed 入站端口不迁移；dae 使用 eBPF 透明代理。局域网设备的网关必须指向本机。"},
		{"warning", "DNS", "DNS 监听独立端口，LAN 客户端到本机 dnsmasq 的 UDP 查询可能绕过 dae；需按 README 接入 dnsmasq，不能仅启动服务。"},
		{"warning", "IPv6", "dns.ipv6=false 时，前置 DNS 对 AAAA 返回 NOERROR 空记录，dae 优先 IPv4；这不禁用操作系统 IPv6，已有 IPv6 地址仍可连接。"},
		{"info", "策略组", "select 通过管理器解析为所选子组或单节点，切换后生成新配置并按应用设置重启或热重载；url-test 使用 min_moving_avg。"},
		{"info", "直连日志", "eBPF 内核直连不保证逐流日志；DNS/分流细节需 debug/trace，面板只展示实际输出。"},
		{"info", "DNS 多上游", "Mihomo 的上游列表取第一项；其余保留在源 YAML。未复制其并行查询与回退语义。"},
		{"info", "不等价选项", "profile、sniffer 端口/排除列表、keep-alive、tcp-concurrent、unified-delay、find-process-mode、external-ui 不直接等价；请查兼容性文档。"},
	} {
		r.Notices = append(r.Notices, n)
	}
	if len(obj(c["hosts"])) > 0 {
		r.note("warning", "hosts", "静态 hosts 由管理器 DNS 前置服务（5353）应答，转发到 dae（5354）。包含 hosts 时禁止绕过前置端口。")
	}
	if e = writeJSON(filepath.Join(stage, "report.json"), r); e != nil {
		return r, e
	}
	return r, nil
}
func makeGroups(c M, r *Report, selections map[string]string) error {
	for _, raw := range seq(c["proxy-groups"]) {
		p := obj(raw)
		g := Group{Name: str(p["name"]), Type: str(p["type"]), Choices: strs(p["proxies"]), Interval: number(p["interval"], 120), Tolerance: number(p["tolerance"], 50), CheckURL: str(p["url"])}
		g.ID = id("g_", g.Name)
		if !in(g.Type, []string{"select", "url-test", "fallback", "load-balance"}) {
			return fmt.Errorf("策略组 %s 类型不支持", g.Name)
		}
		use := strs(p["use"])
		for _, n := range r.Nodes {
			if yes(p["include-all"]) || in(n.Provider, use) {
				ok, e := match(str(p["filter"]), n.Name)
				if e != nil {
					return e
				}
				excluded := false
				if str(p["exclude-filter"]) != "" {
					excluded, e = match(str(p["exclude-filter"]), n.Name)
					if e != nil {
						return e
					}
				}
				if ok && !excluded && !in(n.Name, g.Choices) {
					g.Choices = append(g.Choices, n.Name)
				}
			}
		}
		if g.Type == "select" {
			g.Selected = selections[g.Name]
			if !in(g.Selected, g.Choices) {
				if g.Selected != "" {
					return fmt.Errorf("组 %s 原选择 %s 已消失，须手动重新选择，保留旧配置", g.Name, g.Selected)
				}
				if len(g.Choices) > 0 {
					g.Selected = g.Choices[0]
				}
			}
		} else {
			switch g.Type {
			case "url-test":
				g.Policy = "min_moving_avg"
			case "fallback":
				g.Policy = "min_moving_avg"
				r.note("warning", g.Name, "fallback 转成最小滑动平均延迟，不能等价保证原顺序优先。 ")
			case "load-balance":
				g.Policy = "random"
				r.note("warning", g.Name, "load-balance 转成逐连接随机，不能等价 consistent-hashing。 ")
			}
		}
		r.Groups = append(r.Groups, g)
	}
	names := map[string]bool{}
	for _, g := range r.Groups {
		if g.Name == "" || names[g.Name] {
			return fmt.Errorf("策略组名称为空或重复")
		}
		names[g.Name] = true
	}
	for i := range r.Groups {
		g := &r.Groups[i]
		members, e := groupMembers(g.Name, r.Groups, r.Nodes, map[string]bool{})
		if e != nil {
			return e
		}
		g.Members = members
		builtinOnly := g.Type == "select" && len(g.Choices) > 0
		for _, choice := range g.Choices {
			if !in(choice, []string{"DIRECT", "REJECT", "REJECT-DROP"}) {
				builtinOnly = false
			}
		}
		if len(members) == 0 && !builtinOnly {
			r.note("warning", g.Name, "策略组没有匹配节点；未被规则选中时允许保留，选中时拒绝应用。")
		}
	}
	return nil
}
func groupMembers(name string, groups []Group, nodes []Node, seen map[string]bool) ([]string, error) {
	if seen[name] {
		return nil, fmt.Errorf("策略组引用循环：%s", name)
	}
	for _, n := range nodes {
		if n.Name == name {
			return []string{name}, nil
		}
	}
	if in(name, []string{"DIRECT", "REJECT", "REJECT-DROP"}) {
		return nil, nil
	}
	seen[name] = true
	defer delete(seen, name)
	for _, g := range groups {
		if g.Name == name {
			var out []string
			for _, choice := range g.Choices {
				members, e := groupMembers(choice, groups, nodes, seen)
				if e != nil {
					return nil, e
				}
				for _, n := range members {
					if !in(n, out) {
						out = append(out, n)
					}
				}
			}
			return out, nil
		}
	}
	return nil, fmt.Errorf("未知节点或分组 %s", name)
}
func resolveTarget(name string, groups []Group, nodes []Node, seen map[string]bool) (string, error) {
	if name == "DIRECT" {
		return "direct", nil
	}
	if name == "REJECT" || name == "REJECT-DROP" {
		return "block", nil
	}
	if seen[name] {
		return "", fmt.Errorf("分组引用循环")
	}
	seen[name] = true
	for _, n := range nodes {
		if n.Name == name {
			return id("solo_", name), nil
		}
	}
	for _, g := range groups {
		if g.Name == name {
			if g.Type == "select" {
				return resolveTarget(g.Selected, groups, nodes, seen)
			}
			if len(g.Members) == 0 {
				return "", fmt.Errorf("实际出口组 %s 没有节点", g.Name)
			}
			return g.ID, nil
		}
	}
	return "", fmt.Errorf("规则目标 %s 不存在", name)
}
