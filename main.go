package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "错误：", e)
		os.Exit(1)
	}
}
func flags(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ContinueOnError) }
func printJSON(v any)                 { b, _ := json.MarshalIndent(v, "", "  "); fmt.Println(string(b)) }
func run(args []string) error {
	rootFlags := flags("dae-manager")
	root := rootFlags.String("state", "/etc/dae-manager", "state directory")
	if e := rootFlags.Parse(args); e != nil {
		return e
	}
	args = rootFlags.Args()
	if len(args) == 0 {
		fmt.Println("dae-manager " + Version + "\n命令：init / prepare / update / validate / status / doctor / serve / rollback / ctl / core / helper\n使用 --state 指定数据目录。每个子命令支持 -h。 ")
		return nil
	}
	m, e := openManager(*root)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	switch args[0] {
	case "version":
		fmt.Println(Version)
		return nil
	case "init":
		f := flags("init")
		source := f.String("source", "", "Mihomo YAML path")
		s := m.settings()
		f.StringVar(&s.Listen, "listen", s.Listen, "管理监听 IP:端口")
		f.StringVar(&s.Dae, "dae", s.Dae, "dae executable")
		f.StringVar(&s.Mihomo, "mihomo", s.Mihomo, "MRS decoder executable")
		f.StringVar(&s.LAN, "lan", s.LAN, "LAN interface(s), comma separated")
		f.StringVar(&s.WAN, "wan", s.WAN, "WAN interface(s) for local traffic")
		f.StringVar(&s.DNSBind, "dns-bind", s.DNSBind, "manager DNS frontend; dae uses next port")
		noAuto := f.Bool("no-auto-update", false, "disable scheduler for development")
		if e = f.Parse(args[1:]); e != nil {
			return e
		}
		s.AutoUpdate = !*noAuto
		if e = validateBind(s.Listen); e != nil {
			return e
		}
		_, e = m.init(*source, s)
		if e == nil {
			fmt.Println("初始化完成；管理口令保存在 " + filepath.Join(m.Root, "admin-token"))
		}
		return e
	case "prepare", "update":
		f := flags(args[0])
		rules := f.Bool("rules", false, "refresh rule datasets as well")
		if e = f.Parse(args[1:]); e != nil {
			return e
		}
		unlock, e := m.lock()
		if e != nil {
			return e
		}
		defer unlock()
		if args[0] == "update" {
			return m.update(ctx, *rules)
		}
		id, r, e := m.build(ctx, true, *rules, nil, nil, m.settings())
		if e != nil {
			return e
		}
		if e = m.activate(ctx, id, false); e != nil {
			return e
		}
		printJSON(M{"revision": id, "nodes": len(r.Nodes), "groups": len(r.Groups), "rules": len(r.Rules), "validation": r.Validation})
		return nil
	case "validate":
		return m.validate(ctx, m.currentDir())
	case "status":
		r, _ := m.report()
		printJSON(M{"process": m.coreProcess(), "revision": m.currentID(), "nodes": len(r.Nodes), "validation": r.Validation})
		return nil
	case "doctor":
		printJSON(doctor())
		return nil
	case "rollback":
		if len(args) != 2 {
			return fmt.Errorf("用法：rollback <revision-id>")
		}
		unlock, e := m.lock()
		if e != nil {
			return e
		}
		defer unlock()
		return m.activate(ctx, args[1], false)
	case "serve":
		f := flags("serve")
		noDNS := f.Bool("no-dns", false, "development preview only, disable DNS frontend")
		if e = f.Parse(args[1:]); e != nil {
			return e
		}
		return m.serve(ctx, *noDNS)
	case "core", "helper":
		f := flags(args[0])
		version := f.String("version", "latest", "official release tag")
		arch := f.String("arch", "", "binary architecture")
		dest := f.String("output", "", "executable path")
		if e = f.Parse(args[1:]); e != nil {
			return e
		}
		if args[0] == "core" {
			if *dest == "" {
				*dest = m.settings().Dae
			}
			if m.coreProcess().PID > 0 {
				return fmt.Errorf("升级核心前请停止本管理器的 dae 服务")
			}
			return installCore(ctx, m.Root, *dest, *arch, *version)
		}
		if *dest == "" {
			*dest = m.settings().Mihomo
		}
		return installMihomo(ctx, *dest, *arch, *version)
	case "ctl":
		if len(args) < 2 {
			return fmt.Errorf("用法：ctl status|report|doctor|revisions|logs|update|service [参数]")
		}
		return control(ctx, m, args[1:])
	default:
		return fmt.Errorf("未知命令 %s", args[0])
	}
}
func control(ctx context.Context, m *Manager, args []string) error {
	path := "/api/" + args[0]
	method := "GET"
	var data any
	switch args[0] {
	case "rollback":
		if len(args) != 2 {
			return fmt.Errorf("rollback <revision-id>")
		}
		method = "POST"
		data = M{"revision": args[1]}
	case "service":
		if len(args) != 2 {
			return fmt.Errorf("service start|stop|restart|reload")
		}
		method = "POST"
		data = M{"action": args[1]}
	case "update":
		method = "POST"
		data = M{"rules": len(args) > 1 && args[1] == "rules"}
	case "validate":
		method = "POST"
		data = M{}
	case "status", "report", "doctor", "revisions", "logs":
	default:
		return fmt.Errorf("不支持此 ctl 命令")
	}
	b, _ := json.Marshal(data)
	host, p, _ := net.SplitHostPort(m.settings().Listen)
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	req, e := http.NewRequestWithContext(ctx, method, "http://"+net.JoinHostPort(host, p)+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	token, e := os.ReadFile(filepath.Join(m.Root, "admin-token"))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("X-DAE-Request", "1")
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 15 * time.Second}
	res, e := client.Do(req)
	if e != nil {
		return fmt.Errorf("无法连接后台，请先启动 dae-manager 服务")
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode >= 400 {
		return fmt.Errorf("后台返回 HTTP %d：%s", res.StatusCode, string(out))
	}
	fmt.Println(string(out))
	return nil
}
