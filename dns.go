package main

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (m *Manager) dnsHandler(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) != 1 {
		reply := new(dns.Msg)
		reply.SetRcode(req, dns.RcodeFormatError)
		_ = w.WriteMsg(reply)
		return
	}
	q := req.Question[0]
	m.dnsLog(w.RemoteAddr().String(), q.Name, dns.TypeToString[q.Qtype])
	if q.Qtype == dns.TypeAAAA && !sourceIPv6(m.currentDir()) {
		reply := new(dns.Msg)
		reply.SetReply(req)
		reply.RecursionAvailable = true
		_ = w.WriteMsg(reply)
		return
	}
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	hosts := map[string]any{}
	_ = readJSON(filepath.Join(m.currentDir(), "hosts.json"), &hosts)
	if value, ok := hosts[name]; ok {
		reply := new(dns.Msg)
		reply.SetReply(req)
		reply.Authoritative = true
		values := []string{str(value)}
		if a := strs(value); len(a) > 0 {
			values = a
		}
		for _, ip := range values {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			if q.Qtype == dns.TypeA && parsed.To4() != nil {
				reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: parsed.To4()})
			}
			if q.Qtype == dns.TypeAAAA && parsed.To4() == nil && sourceIPv6(m.currentDir()) {
				reply.Answer = append(reply.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: parsed})
			}
		}
		_ = w.WriteMsg(reply)
		return
	}
	client := &dns.Client{Net: "udp", Timeout: 4 * time.Second}
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		client.Net = "tcp"
	}
	reply, _, e := client.Exchange(req, dnsBackend(m.settings().DNSBind))
	if e == nil && reply.Truncated && client.Net == "udp" {
		client.Net = "tcp"
		reply, _, e = client.Exchange(req, dnsBackend(m.settings().DNSBind))
	}
	if e != nil {
		reply = new(dns.Msg)
		reply.SetRcode(req, dns.RcodeServerFailure)
	}
	_ = w.WriteMsg(reply)
}
func sourceIPv6(dir string) bool {
	b, e := os.ReadFile(filepath.Join(dir, "source.yaml"))
	if e != nil {
		return false
	}
	c, e := parseYAML(b)
	return e == nil && yes(obj(c["dns"])["ipv6"])
}
func (m *Manager) serveDNS(ctx context.Context) error {
	bind := m.settings().DNSBind
	udp, e := net.ListenPacket("udp", bind)
	if e != nil {
		return fmt.Errorf("DNS UDP 监听失败：%w", e)
	}
	tcp, e := net.Listen("tcp", bind)
	if e != nil {
		udp.Close()
		return fmt.Errorf("DNS TCP 监听失败：%w", e)
	}
	slots := make(chan struct{}, 128)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			m.dnsHandler(w, r)
		default:
			reply := new(dns.Msg)
			reply.SetRcode(r, dns.RcodeServerFailure)
			_ = w.WriteMsg(reply)
		}
	})
	us := &dns.Server{PacketConn: udp, Handler: handler, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	ts := &dns.Server{Listener: tcp, Handler: handler, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxTCPQueries: 64}
	go us.ActivateAndServe()
	go ts.ActivateAndServe()
	go func() { <-ctx.Done(); _ = us.Shutdown(); _ = ts.Shutdown() }()
	return nil
}
