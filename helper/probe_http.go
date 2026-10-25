package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type requestPhases struct {
	sync.Mutex
	dialMS, tlsMS, responseMS int64
	tlsAt, wroteAt            time.Time
	reused                    bool
}
type requestPhaseKey struct{}

func (p *requestPhases) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn:           func(info httptrace.GotConnInfo) { p.Lock(); p.reused = info.Reused; p.Unlock() },
		TLSHandshakeStart: func() { p.Lock(); p.tlsAt = time.Now(); p.Unlock() },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { p.Lock(); p.tlsMS = time.Since(p.tlsAt).Milliseconds(); p.Unlock() },
		WroteRequest:      func(httptrace.WroteRequestInfo) { p.Lock(); p.wroteAt = time.Now(); p.Unlock() },
		GotFirstResponseByte: func() {
			p.Lock()
			if !p.wroteAt.IsZero() {
				p.responseMS = time.Since(p.wroteAt).Milliseconds()
			}
			p.Unlock()
		},
	}
}

// Keep both observations. The first includes connection setup; the second can
// be compared with a warm URL test only when Transport confirms actual reuse.
func measureHTTP(ctx context.Context, d netproxy.Dialer, target string, result ProbeResult) ProbeResult {
	if target == "" {
		target = "https://cp.cloudflare.com/generate_204"
	}
	u, e := url.Parse(target)
	if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		result.Message = "测试地址无效"
		return result
	}
	result.URL = u.Scheme + "://" + u.Host + u.EscapedPath()
	tr := &http.Transport{TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 8 * time.Second, IdleConnTimeout: 15 * time.Second, DisableCompression: true}
	defer tr.CloseIdleConnections()
	tr.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
		start := time.Now()
		c, e := d.DialContext(ctx, (netproxy.MagicNetwork{Network: "tcp", IPVersion: "4"}).Encode(), addr)
		if p, ok := ctx.Value(requestPhaseKey{}).(*requestPhases); ok {
			p.Lock()
			p.dialMS += time.Since(start).Milliseconds()
			p.Unlock()
		}
		if e != nil {
			return nil, e
		}
		return &netproxy.FakeNetConn{Conn: c, LAddr: &net.TCPAddr{}, RAddr: &net.TCPAddr{}}, nil
	}
	cli := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for attempt := 0; attempt < 2; attempt++ {
		phases := &requestPhases{}
		reqCtx := context.WithValue(ctx, requestPhaseKey{}, phases)
		reqCtx = httptrace.WithClientTrace(reqCtx, phases.trace())
		req, e := http.NewRequestWithContext(reqCtx, http.MethodHead, target, nil)
		if e != nil {
			result.Message = "测试地址无效"
			return result
		}
		start := time.Now()
		resp, e := cli.Do(req)
		elapsed := time.Since(start).Milliseconds()
		if e != nil {
			if attempt == 0 {
				result.Message = "连接、TLS 握手或请求失败"
				if ctx.Err() != nil {
					result.Message = "测试超时"
				}
			} else {
				result.WarmMessage = "第二次请求失败，保留首次结果"
			}
			return result
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			if attempt == 0 {
				result.Message = fmt.Sprintf("HTTP %d", resp.StatusCode)
			} else {
				result.WarmMessage = fmt.Sprintf("第二次请求 HTTP %d", resp.StatusCode)
			}
			return result
		}
		phases.Lock()
		if attempt == 0 {
			result.OK = true
			result.Millis = &elapsed
			result.Message = "首次 HTTP 请求，含节点建连与 TLS 握手"
			result.DialMS = phases.dialMS
			result.TLSMS = phases.tlsMS
			result.ResponseMS = phases.responseMS
			result.HTTP = resp.Proto
		} else {
			result.WarmMS = &elapsed
			result.WarmReused = phases.reused
			result.WarmMessage = "复用已有 HTTP 连接"
			if !phases.reused {
				result.WarmMessage = "服务端未保留连接，第二次仍需新建连接"
			}
		}
		phases.Unlock()
	}
	return result
}
