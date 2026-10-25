package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	cp "github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/anytls"
	_ "github.com/daeuniverse/outbound/dialer/http"
	_ "github.com/daeuniverse/outbound/dialer/hysteria2"
	_ "github.com/daeuniverse/outbound/dialer/shadowsocks"
	_ "github.com/daeuniverse/outbound/dialer/socks"
	_ "github.com/daeuniverse/outbound/dialer/trojan"
	_ "github.com/daeuniverse/outbound/dialer/tuic"
	_ "github.com/daeuniverse/outbound/dialer/v2ray"
	"github.com/daeuniverse/outbound/netproxy"
	_ "github.com/daeuniverse/outbound/protocol/anytls"
	_ "github.com/daeuniverse/outbound/protocol/vless"
	_ "github.com/daeuniverse/outbound/protocol/vmess"
	"github.com/sirupsen/logrus"
)

type Node struct {
	ID   string `json:"id"`
	URI  string `json:"uri"`
	Type string `json:"type"`
}
type Group struct {
	ID      string   `json:"id"`
	Policy  string   `json:"policy"`
	Members []string `json:"members"`
	Known   bool     `json:"known"`
}
type Rule struct {
	Expression string `json:"expression"`
	Outbound   string `json:"outbound"`
}
type Globals struct {
	LogLevel string `json:"log_level"`
	TLS      string `json:"tls"`
	Imitate  string `json:"imitate"`
	Insecure bool   `json:"insecure"`
	CheckURL string `json:"check_url"`
}
type Inventory struct {
	Nodes    []Node  `json:"nodes"`
	Groups   []Group `json:"groups"`
	Rules    []Rule  `json:"rules"`
	Global   Globals `json:"global"`
	Includes bool    `json:"includes"`
}

func filterMatches(fs []*cp.Function, id string) (bool, bool) {
	for _, f := range fs {
		if f.Name != "name" {
			return false, false
		}
		match := false
		for _, p := range f.Params {
			if p.Key == "regex" {
				re, e := regexp.Compile(p.Val)
				if e != nil {
					return false, false
				}
				match = match || re.MatchString(id)
			} else if p.Key == "" {
				match = match || p.Val == id
			} else {
				return false, false
			}
		}
		if f.Not {
			match = !match
		}
		if !match {
			return false, true
		}
	}
	return true, true
}
func inspect(data []byte) (Inventory, error) {
	out := Inventory{Global: Globals{LogLevel: "info", TLS: "tls", Imitate: "chrome_auto", CheckURL: "https://cp.cloudflare.com/generate_204"}}
	sections, e := cp.Parse(string(data))
	if e != nil {
		return out, e
	}
	var groupSections []*cp.Section
	for _, s := range sections {
		switch s.Name {
		case "include":
			out.Includes = true
		case "node":
			for _, item := range s.Items {
				if p, ok := item.Value.(*cp.Param); ok {
					uri := p.Val
					id := p.Key
					if id == "" {
						h := sha256.Sum256([]byte(uri))
						id = fmt.Sprintf("native_%x", h[:6])
						if at := strings.LastIndex(uri, "#"); at >= 0 {
							if name, e := url.PathUnescape(uri[at+1:]); e == nil && name != "" {
								id = name
							}
						}
					}
					scheme, _, ok := strings.Cut(uri, "://")
					if ok {
						out.Nodes = append(out.Nodes, Node{ID: id, URI: uri, Type: scheme})
					}
				}
			}
		case "global":
			for _, item := range s.Items {
				if p, ok := item.Value.(*cp.Param); ok {
					switch p.Key {
					case "log_level":
						out.Global.LogLevel = p.Val
					case "tls_implementation":
						out.Global.TLS = p.Val
					case "utls_imitate":
						out.Global.Imitate = p.Val
					case "allow_insecure":
						out.Global.Insecure = p.Val == "true"
					case "tcp_check_url":
						out.Global.CheckURL = strings.Split(p.Val, ",")[0]
					}
				}
			}
		case "group":
			for _, item := range s.Items {
				if child, ok := item.Value.(*cp.Section); ok {
					groupSections = append(groupSections, child)
				}
			}
		case "routing":
			for _, item := range s.Items {
				switch v := item.Value.(type) {
				case *cp.RoutingRule:
					var expr []string
					for _, f := range v.AndFunctions {
						expr = append(expr, f.MarshalString(false, true, false))
					}
					out.Rules = append(out.Rules, Rule{strings.Join(expr, " && "), v.Outbound.Name})
				case *cp.Param:
					if v.Key == "fallback" {
						value := v.Val
						if len(v.AndFunctions) > 0 {
							value = v.AndFunctions[0].Name
						}
						out.Rules = append(out.Rules, Rule{"fallback", value})
					}
				}
			}
		}
	}
	for _, s := range groupSections {
		g := Group{ID: s.Name, Known: true, Members: []string{}}
		var filters [][]*cp.Function
		for _, item := range s.Items {
			if p, ok := item.Value.(*cp.Param); ok {
				if p.Key == "filter" {
					filters = append(filters, p.AndFunctions)
				}
				if p.Key == "policy" {
					g.Policy = p.Val
					if len(p.AndFunctions) > 0 {
						g.Policy = p.AndFunctions[0].MarshalString(false, true, false)
					}
				}
			}
		}
		for _, n := range out.Nodes {
			matched := len(filters) == 0
			for _, fs := range filters {
				yes, known := filterMatches(fs, n.ID)
				g.Known = g.Known && known
				matched = matched || yes
			}
			if matched {
				g.Members = append(g.Members, n.ID)
			}
		}
		out.Groups = append(out.Groups, g)
	}
	return out, nil
}

type scoped struct {
	netproxy.Dialer
	namespace string
}

func (s scoped) TransportCacheNamespace() string { return s.namespace }

type ProbeRequest struct {
	Nodes  []Node  `json:"nodes"`
	Global Globals `json:"global"`
	DNS    string  `json:"dns"`
}
type ProbeResult struct {
	ID          string    `json:"id"`
	OK          bool      `json:"ok"`
	Millis      *int64    `json:"ms"`
	Message     string    `json:"message"`
	CheckedAt   time.Time `json:"checked_at"`
	WarmMS      *int64    `json:"warm_ms,omitempty"`
	WarmReused  bool      `json:"warm_reused"`
	WarmMessage string    `json:"warm_message,omitempty"`
	DialMS      int64     `json:"dial_ms,omitempty"`
	TLSMS       int64     `json:"tls_ms,omitempty"`
	ResponseMS  int64     `json:"response_ms,omitempty"`
	URL         string    `json:"url,omitempty"`
	HTTP        string    `json:"http,omitempty"`
}

func probe(n Node, g Globals) (result ProbeResult) {
	result = ProbeResult{ID: n.ID, CheckedAt: time.Now()}
	defer func() {
		result.CheckedAt = time.Now()
		if recover() != nil {
			result.Message = "探测程序未能完成"
		}
	}()
	options := &dialer.ExtraOption{TlsImplementation: g.TLS, UtlsImitate: g.Imitate, AllowInsecure: g.Insecure, UDPHopInterval: 30 * time.Second}
	base, _ := dialer.NewDirectDialer(options, false)
	d, _, err := dialer.NewNetproxyDialerFromLink(scoped{base, n.ID + strconv.FormatInt(time.Now().UnixNano(), 10)}, options, n.ID+":"+n.URI)
	if err != nil {
		result.Message = "节点参数无法解析"
		return
	}
	if closer, ok := d.(io.Closer); ok {
		defer closer.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return measureHTTP(ctx, d, g.CheckURL, result)
}
func main() {
	logrus.SetOutput(io.Discard)
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "inspect":
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if e != nil {
			os.Exit(2)
		}
		inv, e := inspect(b)
		if e != nil {
			fmt.Fprintln(os.Stderr, "dae 解析失败:", e)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(inv)
	case "probe":
		f := flag.NewFlagSet("probe", flag.ExitOnError)
		workers := f.Int("workers", 4, "parallel nodes")
		f.Parse(os.Args[2:])
		var req ProbeRequest
		if json.NewDecoder(os.Stdin).Decode(&req) != nil {
			os.Exit(2)
		}
		if req.DNS == "" {
			req.DNS = "127.0.0.1:5353"
		}
		net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, req.DNS)
		}}
		in := make(chan Node)
		out := make(chan ProbeResult)
		var wg sync.WaitGroup
		for i := 0; i < *workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for n := range in {
					out <- probe(n, req.Global)
				}
			}()
		}
		go func() {
			for _, n := range req.Nodes {
				in <- n
			}
			close(in)
			wg.Wait()
			close(out)
		}()
		enc := json.NewEncoder(os.Stdout)
		for r := range out {
			enc.Encode(r)
		}
	default:
		os.Exit(2)
	}
}
