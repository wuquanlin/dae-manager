package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func sortStrings(a []string)        { sort.Strings(a) }
func digest(b []byte) string        { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func id(prefix, name string) string { return prefix + digest([]byte(name))[:12] }
func fetch(ctx context.Context, raw string, headers M) ([]byte, error) {
	var e error
	for attempt := 0; attempt < 3; attempt++ {
		var b []byte
		b, e = fetchOnce(ctx, raw, headers)
		if e == nil {
			return b, nil
		}
		if !strings.Contains(e.Error(), "下载失败") && !strings.Contains(e.Error(), "读取数据失败") && !strings.Contains(e.Error(), "HTTP 5") && !strings.Contains(e.Error(), "HTTP 429") {
			return nil, e
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("下载已取消")
			case <-time.After(time.Duration(attempt+1) * time.Second):
			}
		}
	}
	return nil, e
}
func fetchOnce(ctx context.Context, raw string, headers M) ([]byte, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || !in(u.Scheme, []string{"http", "https"}) {
		return nil, fmt.Errorf("仅允许 HTTP(S) 数据源")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if e != nil {
		return nil, fmt.Errorf("无效下载请求")
	}
	req.Header.Set("User-Agent", "clash.meta/dae-manager")
	for k, v := range headers {
		if a := strs(v); len(a) > 0 {
			req.Header.Set(k, a[0])
		} else {
			req.Header.Set(k, str(v))
		}
	}
	client := &http.Client{Timeout: 120 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return fmt.Errorf("重定向过多")
		}
		if r.URL.Scheme != "https" && via[0].URL.Scheme == "https" {
			return fmt.Errorf("拒绝 HTTPS 降级")
		}
		if r.URL.Host != via[0].URL.Host {
			for k := range headers {
				r.Header.Del(k)
			}
			r.Header.Del("Authorization")
		}
		return nil
	}}
	resp, e := client.Do(req)
	if e != nil {
		return nil, fmt.Errorf("下载失败（网络或 TLS 错误，链接已隐藏）")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("下载返回 HTTP %d", resp.StatusCode)
	}
	const max = 32 << 20
	b, e := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if e != nil {
		return nil, fmt.Errorf("读取数据失败")
	}
	if len(b) > max {
		return nil, fmt.Errorf("单个数据源超过 32 MiB 上限")
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("数据源为空")
	}
	return b, nil
}
func cachedFetch(ctx context.Context, cache string, p M, refresh bool) ([]byte, error) {
	if str(p["type"]) == "inline" {
		return nil, fmt.Errorf("inline 由调用者处理")
	}
	raw := str(p["url"])
	key := digest([]byte(raw + fmt.Sprint(p["header"])))
	path := filepath.Join(cache, key)
	if !refresh {
		if b, e := os.ReadFile(path); e == nil && len(b) > 0 {
			return b, nil
		}
	}
	b, e := fetch(ctx, raw, obj(p["header"]))
	if e != nil {
		return nil, e
	}
	if e = atomicWrite(path, b, 0600); e != nil {
		return nil, e
	}
	return b, nil
}
