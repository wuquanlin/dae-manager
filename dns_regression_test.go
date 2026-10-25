package main

import (
	"context"
	"github.com/miekg/dns"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPv6DisabledReturnsNoErrorNoData(t *testing.T) {
	m, _ := setup(t)
	id := buildFixture(t, m)
	if e := m.activate(context.Background(), id, false); e != nil {
		t.Fatal(e)
	}
	r := new(dns.Msg)
	r.SetQuestion("external.example.org.", dns.TypeAAAA)
	w := &captureDNS{}
	m.dnsHandler(w, r)
	if w.msg == nil || w.msg.Rcode != dns.RcodeSuccess || len(w.msg.Answer) != 0 {
		t.Fatal("AAAA suppression must be NOERROR/NODATA, not refusal")
	}
	config, _ := os.ReadFile(filepath.Join(m.currentDir(), "config.dae"))
	if strings.Contains(string(config), "qtype(28) -> reject") || !strings.Contains(string(config), "ipversion_prefer: 4") {
		t.Fatal("generated config rejects IPv4/IPv6 parallel resolver queries")
	}
}
func TestReservedInterfaceRejected(t *testing.T) {
	s := defaultSettings("")
	s.LAN = "dae0"
	if s.validate() == nil {
		t.Fatal("internal interface collision accepted")
	}
}
