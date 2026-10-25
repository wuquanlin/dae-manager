package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestInterruptedDownloadRetriesEntireBody(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.Header().Set("Content-Length", "100")
			fmt.Fprint(w, "partial")
			return
		}
		fmt.Fprint(w, "complete")
	}))
	defer server.Close()
	body, e := fetch(context.Background(), server.URL, nil)
	if e != nil || string(body) != "complete" || attempts.Load() != 2 {
		t.Fatalf("interrupted download did not retry: %v attempts=%d", e, attempts.Load())
	}
}
