package main

import (
	"context"
	"github.com/daeuniverse/outbound/netproxy"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type localTestDialer struct {
	calls atomic.Int32
	delay time.Duration
}

func (d *localTestDialer) DialContext(ctx context.Context, _, addr string) (netproxy.Conn, error) {
	d.calls.Add(1)
	select {
	case <-time.After(d.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}
func TestFirstRequestAndReusedMeasurement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(20 * time.Millisecond); w.WriteHeader(204) }))
	defer server.Close()
	d := &localTestDialer{delay: 60 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	v := measureHTTP(ctx, d, server.URL, ProbeResult{ID: "test"})
	if !v.OK || v.Millis == nil || v.WarmMS == nil || !v.WarmReused || d.calls.Load() != 1 {
		t.Fatalf("unexpected connection measurements: %+v, dials %d", v, d.calls.Load())
	}
	if *v.Millis < 75 || *v.WarmMS >= *v.Millis || v.DialMS < 50 || v.ResponseMS < 15 {
		t.Fatalf("connection setup not distinguished: %+v", v)
	}
}
func TestConnectionCloseNotReportedAsWarm(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(204)
	}))
	defer server.Close()
	d := &localTestDialer{}
	v := measureHTTP(context.Background(), d, server.URL, ProbeResult{})
	if !v.OK || v.WarmMS == nil || v.WarmReused || d.calls.Load() != 2 {
		t.Fatalf("closed connection falsely labeled reused: %+v", v)
	}
}
func TestWarmFailureKeepsFirstSuccess(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 2 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	v := measureHTTP(context.Background(), &localTestDialer{}, server.URL, ProbeResult{})
	if !v.OK || v.Millis == nil || v.WarmMS != nil || v.WarmMessage == "" {
		t.Fatalf("warm failure overwrote first observation: %+v", v)
	}
}
func TestProbeDoesNotFollowRedirect(t *testing.T) {
	var followed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			followed.Add(1)
			w.WriteHeader(204)
			return
		}
		w.Header().Set("Location", "/target")
		w.WriteHeader(302)
	}))
	defer server.Close()
	v := measureHTTP(context.Background(), &localTestDialer{}, server.URL, ProbeResult{})
	if !v.OK || followed.Load() != 0 {
		t.Fatal("probe followed redirect and mixed target measurements")
	}
}
