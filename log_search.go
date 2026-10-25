package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type protoField struct {
	number int
	data   []byte
	value  uint64
}

func protoFields(b []byte) []protoField {
	var out []protoField
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			break
		}
		b = b[n:]
		p := protoField{number: int(tag >> 3)}
		switch tag & 7 {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return out
			}
			p.value = v
			b = b[n:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return out
			}
			b = b[n:]
			p.data = b[:int(l)]
			b = b[int(l):]
		default:
			return out
		}
		out = append(out, p)
	}
	return out
}

type domainMatch struct {
	kind  uint64
	value string
	re    *regexp.Regexp
}
type NetflixIndex struct {
	Revision string
	Domains  []domainMatch
	IPs      []netip.Prefix
}

func (m *Manager) netflixIndex() NetflixIndex {
	m.aliasMu.Lock()
	defer m.aliasMu.Unlock()
	rev := m.currentID()
	if m.netflix.Revision == rev {
		return m.netflix
	}
	index := NetflixIndex{Revision: rev}
	r, _ := m.report()
	tags := map[string]bool{}
	for _, p := range r.Providers {
		if strings.Contains(strings.ToLower(p.Name), "netflix") {
			tags[id("r_", p.Name)] = true
		}
	}
	for _, file := range []string{"rules-site.dat", "rules-ip.dat"} {
		b, _ := os.ReadFile(filepath.Join(m.currentDir(), file))
		for _, entry := range protoFields(b) {
			if entry.number != 1 {
				continue
			}
			parts := protoFields(entry.data)
			tag := ""
			for _, p := range parts {
				if p.number == 1 {
					tag = string(p.data)
				}
			}
			if !tags[tag] {
				continue
			}
			for _, p := range parts {
				if p.number != 2 {
					continue
				}
				fields := protoFields(p.data)
				if file == "rules-site.dat" {
					d := domainMatch{}
					for _, v := range fields {
						if v.number == 1 {
							d.kind = v.value
						}
						if v.number == 2 {
							d.value = strings.ToLower(string(v.data))
						}
					}
					if d.kind == 1 {
						d.re, _ = regexp.Compile(d.value)
					}
					if d.value != "" {
						index.Domains = append(index.Domains, d)
					}
				} else {
					var addr netip.Addr
					var bits int
					for _, v := range fields {
						if v.number == 1 {
							addr, _ = netip.AddrFromSlice(v.data)
						}
						if v.number == 2 {
							bits = int(v.value)
						}
					}
					if addr.IsValid() && bits >= 0 && bits <= addr.BitLen() {
						index.IPs = append(index.IPs, netip.PrefixFrom(addr, bits).Masked())
					}
				}
			}
		}
	}
	m.netflix = index
	return index
}

var domainTokenRE = regexp.MustCompile(`(?i)(?:[a-z0-9_-]+\.)+[a-z][a-z0-9-]{1,62}`)

func enrichNetflix(line string, index NetflixIndex) string {
	lower := strings.ToLower(line)
	for _, domain := range domainTokenRE.FindAllString(lower, -1) {
		for _, suffix := range []string{"netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflximg.com", "nflxext.com", "nflxso.net", "nflxsearch.net", "nflxstatus.com"} {
			if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
				return line + " [Netflix · 域名识别]"
			}
		}
		for _, d := range index.Domains {
			matched := false
			switch d.kind {
			case 0:
				matched = strings.Contains(domain, d.value)
			case 1:
				matched = d.re != nil && d.re.MatchString(domain)
			case 2:
				matched = domain == d.value || strings.HasSuffix(domain, "."+d.value)
			case 3:
				matched = domain == d.value
			}
			if matched {
				return line + " [Netflix · 域名规则集识别]"
			}
		}
	}
	f := fieldsLog(line)
	for _, key := range []string{"ip", "dialIp", "remote_ip", "dst"} {
		value := f[key]
		if host, _, e := net.SplitHostPort(value); e == nil {
			value = host
		}
		ip, e := netip.ParseAddr(value)
		if e != nil {
			continue
		}
		for _, p := range index.IPs {
			if p.Contains(ip) {
				return line + " [Netflix · 目标 IP 命中规则集，推断]"
			}
		}
	}
	return line
}
func (m *Manager) dnsLog(client, name, qtype string) {
	s := m.settings()
	if s.LogLevel != "debug" && s.LogLevel != "trace" {
		return
	}
	m.logMu.Lock()
	defer m.logMu.Unlock()
	path := filepath.Join(m.Root, "dns.log")
	if st, e := os.Stat(path); e == nil && st.Size() > 5<<20 {
		_ = os.Rename(path, path+".1")
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] DEBUG DNS query client=%q qname=%q qtype=%s\n", time.Now().Format("2006-01-02 15:04:05"), client, name, qtype)
}
