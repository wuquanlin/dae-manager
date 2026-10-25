package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(s) + `"`
}
func field(b []byte, n int, p []byte) []byte {
	b = binary.AppendUvarint(b, uint64(n<<3|2))
	b = binary.AppendUvarint(b, uint64(len(p)))
	return append(b, p...)
}
func vint(b []byte, n int, v uint64) []byte {
	b = binary.AppendUvarint(b, uint64(n<<3))
	return binary.AppendUvarint(b, v)
}

type geoBuilder struct{ sites, ips []byte }

func domainPattern(s string) (kind uint64, value string) {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(s, "+.") {
		return 2, strings.TrimPrefix(s, "+.")
	}
	if strings.HasPrefix(s, ".") {
		return 1, `^.+\.` + regexp.QuoteMeta(s[1:]) + `$`
	}
	if strings.Contains(s, "*") {
		r := regexp.QuoteMeta(s)
		r = strings.ReplaceAll(r, `\*`, `[^.]+`)
		return 1, "^" + r + "$"
	}
	return 3, s
}
func (g *geoBuilder) add(name, behavior string, lines []string) error {
	entry := field(nil, 1, []byte(name))
	count := 0
	for _, s := range lines {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") {
			continue
		}
		count++
		if behavior == "domain" {
			k, v := domainPattern(s)
			entry = field(entry, 2, field(vint(nil, 1, k), 2, []byte(v)))
		} else {
			p, e := netip.ParsePrefix(s)
			if e != nil {
				a, e2 := netip.ParseAddr(s)
				if e2 != nil {
					return fmt.Errorf("规则集含无效 CIDR")
				}
				p = netip.PrefixFrom(a, a.BitLen())
			}
			p = p.Masked()
			cidr := field(nil, 1, p.Addr().AsSlice())
			cidr = vint(cidr, 2, uint64(p.Bits()))
			entry = field(entry, 2, cidr)
		}
	}
	if count == 0 {
		return fmt.Errorf("规则集为空")
	}
	if behavior == "domain" {
		g.sites = field(g.sites, 1, entry)
	} else {
		g.ips = field(g.ips, 1, entry)
	}
	return nil
}

type compiledSet struct {
	Behavior      string
	ID            string
	Lines         []string
	Count         int
	PackedDomains int
	PackedIPs     int
}

// A classical set is an OR of conditions sharing one outbound. Domain and
// destination-IP conditions can therefore be packed into two adjacent DAT
// references without changing priority relative to surrounding source rules.
// Keep other condition types inline rather than changing their meaning.
func (g *geoBuilder) packClassical(s *compiledSet) (bool, error) {
	entry := field(nil, 1, []byte(s.ID))
	domains := 0
	var ips []string
	for _, line := range s.Lines {
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			return false, fmt.Errorf("classical 规则缺少条件")
		}
		kind, value := parts[0], parts[1]
		var domainType uint64
		switch kind {
		case "DOMAIN":
			domainType = 3
		case "DOMAIN-SUFFIX":
			domainType = 2
		case "DOMAIN-KEYWORD":
			domainType = 0
		case "DOMAIN-REGEX":
			domainType = 1
		case "IP-CIDR", "IP-CIDR6":
			if _, err := ruleExpr(kind, value); err != nil {
				return false, err
			}
			ips = append(ips, value)
			continue
		default:
			return false, nil
		}
		if value == "" {
			return false, fmt.Errorf("classical 域名条件为空")
		}
		if _, err := ruleExpr(kind, value); err != nil {
			return false, err
		}
		entry = field(entry, 2, field(vint(nil, 1, domainType), 2, []byte(value)))
		domains++
	}
	if domains == 0 && len(ips) == 0 {
		return false, fmt.Errorf("classical 规则集为空")
	}
	if len(ips) > 0 {
		if err := g.add(s.ID, "ipcidr", ips); err != nil {
			return false, err
		}
	}
	if domains > 0 {
		g.sites = field(g.sites, 1, entry)
	}
	s.PackedDomains, s.PackedIPs = domains, len(ips)
	return true, nil
}

func loadRuleSet(ctx context.Context, name string, p M, cache, stage, mihomo string, refresh bool) (compiledSet, ProviderInfo, error) {
	behavior := str(p["behavior"])
	format := str(p["format"])
	if format == "" {
		format = "yaml"
	}
	set := compiledSet{Behavior: behavior, ID: id("r_", name)}
	info := ProviderInfo{Name: name, Kind: "rules"}
	var b []byte
	var e error
	if str(p["type"]) == "inline" {
		b, e = yaml.Marshal(M{"payload": p["payload"]})
		format = "yaml"
	} else {
		b, e = cachedFetch(ctx, cache, p, refresh)
	}
	if e != nil {
		return set, info, fmt.Errorf("规则集 %s：%w", name, e)
	}
	info.Digest = digest(b)
	if format == "mrs" {
		if !in(behavior, []string{"domain", "ipcidr"}) {
			return set, info, fmt.Errorf("MRS 只支持 domain/ipcidr")
		}
		decoded := filepath.Join(cache, digest(append(b, []byte(behavior)...))+".text")
		if old, e := os.ReadFile(decoded); e == nil {
			b = old
		} else {
			inFile := filepath.Join(stage, "decode.mrs")
			outFile := filepath.Join(stage, "decode.txt")
			if e = atomicWrite(inFile, b, 0600); e != nil {
				return set, info, e
			}
			tc, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(tc, mihomo, "convert-ruleset", behavior, "mrs", inFile, outFile)
			if e = cmd.Run(); e != nil {
				return set, info, fmt.Errorf("规则集 %s 的 MRS 解码失败，请安装对应架构的 mihomo 辅助程序", name)
			}
			b, e = os.ReadFile(outFile)
			os.Remove(inFile)
			os.Remove(outFile)
			if e != nil {
				return set, info, e
			}
			if e = atomicWrite(decoded, b, 0600); e != nil {
				return set, info, e
			}
		}
		format = "text"
	}
	if format == "yaml" {
		var payload struct {
			Payload []string `yaml:"payload"`
		}
		if e = yaml.Unmarshal(b, &payload); e != nil {
			return set, info, fmt.Errorf("规则集 %s 的 YAML 无效", name)
		}
		set.Lines = payload.Payload
	} else if format == "text" {
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 4096), 1<<20)
		for sc.Scan() {
			s := strings.TrimSpace(sc.Text())
			if s != "" && !strings.HasPrefix(s, "#") && !strings.HasPrefix(s, "//") {
				set.Lines = append(set.Lines, s)
			}
		}
		if e = sc.Err(); e != nil {
			return set, info, e
		}
	} else {
		return set, info, fmt.Errorf("规则集 %s 的格式不支持", name)
	}
	set.Count = len(set.Lines)
	info.Count = set.Count
	if set.Count == 0 {
		return set, info, fmt.Errorf("规则集 %s 为空，拒绝替换旧配置", name)
	}
	return set, info, nil
}

func ruleExpr(kind, value string) (string, error) {
	switch strings.ToUpper(kind) {
	case "DOMAIN":
		return "domain(full: " + quote(value) + ")", nil
	case "DOMAIN-SUFFIX":
		return "domain(suffix: " + quote(value) + ")", nil
	case "DOMAIN-KEYWORD":
		return "domain(keyword: " + quote(value) + ")", nil
	case "DOMAIN-REGEX":
		if _, e := regexp.Compile(value); e != nil {
			return "", fmt.Errorf("域名正则不兼容 RE2")
		}
		return "domain(regex: " + quote(value) + ")", nil
	case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR":
		p, e := netip.ParsePrefix(value)
		if e != nil {
			return "", fmt.Errorf("无效 CIDR")
		}
		fn := "dip"
		if kind == "SRC-IP-CIDR" {
			fn = "sip"
		}
		return fn + "(" + quote(p.String()) + ")", nil
	case "GEOIP":
		return "dip(ext: " + quote("geoip.dat:"+strings.ToLower(value)) + ")", nil
	case "GEOSITE":
		return "domain(ext: " + quote("geosite.dat:"+strings.ToLower(value)) + ")", nil
	case "DST-PORT", "SRC-PORT":
		fn := "dport"
		if kind == "SRC-PORT" {
			fn = "sport"
		}
		if !regexp.MustCompile(`^\d+(-\d+)?$`).MatchString(value) {
			return "", fmt.Errorf("端口范围无效")
		}
		return fn + "(" + value + ")", nil
	case "NETWORK":
		if !in(strings.ToLower(value), []string{"tcp", "udp"}) {
			return "", fmt.Errorf("传输层协议无效")
		}
		return "l4proto(" + strings.ToLower(value) + ")", nil
	case "PROCESS-NAME":
		return "pname(" + quote(value) + ")", nil
	default:
		return "", fmt.Errorf("尚不支持规则类型 %s", kind)
	}
}
func expressions(kind, value string, sets map[string]compiledSet) ([]string, error) {
	if kind != "RULE-SET" {
		x, e := ruleExpr(kind, value)
		return []string{x}, e
	}
	s, ok := sets[value]
	if !ok {
		return nil, fmt.Errorf("找不到规则集 %s", value)
	}
	switch s.Behavior {
	case "domain":
		return []string{"domain(ext: " + quote("rules-site.dat:"+s.ID) + ")"}, nil
	case "ipcidr":
		return []string{"dip(ext: " + quote("rules-ip.dat:"+s.ID) + ")"}, nil
	case "classical":
		if s.PackedDomains > 0 || s.PackedIPs > 0 {
			var out []string
			if s.PackedDomains > 0 {
				out = append(out, "domain(ext: "+quote("rules-site.dat:"+s.ID)+")")
			}
			if s.PackedIPs > 0 {
				out = append(out, "dip(ext: "+quote("rules-ip.dat:"+s.ID)+")")
			}
			return out, nil
		}
		var out []string
		for _, line := range s.Lines {
			parts := strings.Split(line, ",")
			if len(parts) < 2 {
				return nil, fmt.Errorf("classical 规则缺少条件")
			}
			x, e := ruleExpr(parts[0], parts[1])
			if e != nil {
				return nil, e
			}
			out = append(out, x)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("未知规则集行为 %s", s.Behavior)
	}
}
