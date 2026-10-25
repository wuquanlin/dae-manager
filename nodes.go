package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Node secrets are emitted only into private revision files, never the status API.
func nodeURI(n M, report *Report) (string, error) {
	typ := str(n["type"])
	name := str(n["name"])
	server := str(n["server"])
	port := number(n["port"], 0)
	if name == "" || server == "" || port < 1 || port > 65535 {
		return "", fmt.Errorf("节点缺少名称、服务器或有效端口")
	}
	for _, key := range []string{"dialer-proxy", "smux", "ech-opts", "xhttp-opts", "http-opts"} {
		if v, ok := n[key]; ok && v != nil {
			return "", fmt.Errorf("节点 %s 的 %s 尚不能等价转换", name, key)
		}
	}
	u := url.URL{Scheme: typ, Host: net.JoinHostPort(server, fmt.Sprint(port)), Fragment: name}
	q := url.Values{}
	sni := str(n["servername"])
	if sni == "" {
		sni = str(n["sni"])
	}
	if sni != "" {
		q.Set("sni", sni)
	}
	if yes(n["skip-cert-verify"]) {
		q.Set("insecure", "1")
		q.Set("allowInsecure", "1")
		q.Set("allow_insecure", "1")
		report.note("warning", name, "源节点关闭证书校验；部分 dae 协议实现不读取此参数。请优先修复证书，未全局关闭验证。")
	}
	if a := strs(n["alpn"]); len(a) > 0 {
		q.Set("alpn", strings.Join(a, ","))
	}
	fp := str(n["client-fingerprint"])
	if fp == "" {
		fp = str(n["fp"])
	}
	if fp != "" {
		q.Set("fp", fp)
	}
	switch typ {
	case "vless", "vmess":
		network := str(n["network"])
		if network == "" {
			network = "tcp"
		}
		if !in(network, []string{"tcp", "ws", "grpc", "httpupgrade", "h2", "http"}) {
			return "", fmt.Errorf("节点 %s 的传输 %s 不支持", name, network)
		}
		q.Set("type", network)
		q.Set("encryption", "none")
		q.Set("security", "none")
		if yes(n["tls"]) {
			q.Set("security", "tls")
		}
		q.Set("flow", str(n["flow"]))
		if r := obj(n["reality-opts"]); len(r) > 0 {
			q.Set("security", "reality")
			q.Set("pbk", str(r["public-key"]))
			q.Set("sid", str(r["short-id"]))
			q.Set("spx", str(r["spider-x"]))
		}
		ws := obj(n["ws-opts"])
		if network == "httpupgrade" {
			ws = obj(n["http-upgrade-opts"])
		}
		if len(ws) > 0 {
			q.Set("path", str(ws["path"]))
			q.Set("host", str(obj(ws["headers"])["Host"]))
			for _, k := range []string{"max-early-data", "early-data-header-name"} {
				if ws[k] != nil {
					return "", fmt.Errorf("节点 %s 的 WS early-data 尚未支持", name)
				}
			}
		}
		if network == "grpc" {
			q.Set("serviceName", str(obj(n["grpc-opts"])["grpc-service-name"]))
		}
		if typ == "vmess" {
			if number(n["alterId"], 0) != 0 {
				return "", fmt.Errorf("VMess 非 AEAD 节点不支持")
			}
			m := M{"v": "2", "ps": name, "add": server, "port": fmt.Sprint(port), "id": str(n["uuid"]), "aid": "0", "net": network, "type": "none", "host": q.Get("host"), "path": q.Get("path"), "sni": sni, "tls": q.Get("security"), "alpn": q.Get("alpn"), "allowInsecure": yes(n["skip-cert-verify"])}
			if network == "grpc" {
				m["path"] = q.Get("serviceName")
			}
			b, _ := json.Marshal(m)
			return "vmess://" + base64.RawStdEncoding.EncodeToString(b), nil
		}
		if str(n["uuid"]) == "" {
			return "", fmt.Errorf("VLESS UUID 为空")
		}
		u.User = url.User(str(n["uuid"]))
	case "hysteria2", "hy2":
		u.Scheme = "hysteria2"
		u.User = url.User(str(n["password"]))
		// dae supports port hopping through its own extended address parser.
		if ports := str(n["ports"]); ports != "" {
			u.Host = net.JoinHostPort(server, ports)
			report.note("info", name, "保留 Hysteria2 跳端口范围；跳端口间隔使用 dae 默认值。")
		}
		for _, k := range []string{"obfs", "obfs-password"} {
			if n[k] != nil {
				q.Set(k, str(n[k]))
			}
		}
		if n["up"] != nil {
			q.Set("upmbps", str(n["up"]))
		}
		if n["down"] != nil {
			q.Set("downmbps", str(n["down"]))
		}
		if n["fingerprint"] != nil {
			q.Set("pinSHA256", str(n["fingerprint"]))
		}
	case "anytls", "trojan":
		u.User = url.User(str(n["password"]))
		if typ == "trojan" {
			network := str(n["network"])
			if network != "" && network != "tcp" {
				return "", fmt.Errorf("Trojan 非 TCP 传输暂不转换")
			}
		}
	case "ss":
		u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(str(n["cipher"]) + ":" + str(n["password"]))))
		if n["plugin"] != nil {
			return "", fmt.Errorf("SS 插件须人工核对，拒绝静默删除")
		}
	case "socks5", "http":
		if yes(n["tls"]) {
			if typ == "http" {
				u.Scheme = "https"
			} else {
				return "", fmt.Errorf("Socks TLS 暂不支持")
			}
		}
		if n["username"] != nil {
			u.User = url.UserPassword(str(n["username"]), str(n["password"]))
		}
	case "tuic":
		u.User = url.UserPassword(str(n["uuid"]), str(n["password"]))
		q.Set("congestion_control", str(n["congestion-controller"]))
		q.Set("udp_relay_mode", str(n["udp-relay-mode"]))
	default:
		return "", fmt.Errorf("节点 %s 的协议 %s 尚不支持", name, typ)
	}
	// Transport tuning is intentionally reported rather than claimed equivalent.
	for _, k := range []string{"packet-encoding", "fast-open", "tfo", "udp", "client-fingerprint", "alpn"} {
		if n[k] != nil {
			report.note("info", name, "参数 "+k+" 由 dae 协议实现决定，不保证与 Mihomo 完全一致。")
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
