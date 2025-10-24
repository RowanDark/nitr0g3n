package netutil

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/yourusername/nitr0g3n/ratelimit"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestNewHTTPClientDefaults(t *testing.T) {
	client := NewHTTPClient(0, nil)
	if client.Timeout != 30*time.Second {
		t.Fatalf("expected default timeout, got %s", client.Timeout)
	}
	rt, ok := client.Transport.(*coalescingRoundTripper)
	if !ok {
		t.Fatalf("expected coalescing transport, got %T", client.Transport)
	}
	if _, ok := rt.base.(*retryRoundTripper); !ok {
		t.Fatalf("expected retry transport as base, got %T", rt.base)
	}
}

func TestNewHTTPClientWithLimiter(t *testing.T) {
	limiter := ratelimit.New(1)
	client := NewHTTPClient(5*time.Second, limiter)
	lrt, ok := client.Transport.(*limitingRoundTripper)
	if !ok {
		t.Fatalf("expected limiting round tripper, got %T", client.Transport)
	}
	if lrt.limiter == nil {
		t.Fatalf("expected limiter to be set")
	}
	if _, ok := lrt.base.(*coalescingRoundTripper); !ok {
		t.Fatalf("expected coalescing transport under limiter, got %T", lrt.base)
	}
}

func TestLimitingRoundTripperHonoursContext(t *testing.T) {
	limiter := ratelimit.New(1)
	if err := limiter.Acquire(context.Background()); err != nil {
		t.Fatalf("failed to acquire token: %v", err)
	}
	rt := &limitingRoundTripper{base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("should not reach base")
	}), limiter: limiter}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatalf("expected context cancellation error")
	}
}

func TestCoalescingRoundTripperDeduplicates(t *testing.T) {
	var (
		calls int
		mu    sync.Mutex
	)
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		body := io.NopCloser(bytes.NewBufferString("ok"))
		return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
	})

	crt := &coalescingRoundTripper{base: base}

	const workers = 5
	var wg sync.WaitGroup
	wg.Add(workers)
	results := make([]string, workers)
	start := make(chan struct{})

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			if err != nil {
				t.Errorf("failed to create request: %v", err)
				return
			}
			<-start
			resp, err := crt.RoundTrip(req)
			if err != nil {
				t.Errorf("round trip failed: %v", err)
				return
			}
			defer resp.Body.Close()
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("failed to read response: %v", err)
				return
			}
			results[idx] = string(data)
		}(i)
	}

	close(start)
	wg.Wait()

	mu.Lock()
	totalCalls := calls
	mu.Unlock()

	if totalCalls != 1 {
		t.Fatalf("expected single upstream call, got %d", totalCalls)
	}

	for i, result := range results {
		if result != "ok" {
			t.Fatalf("unexpected body at index %d: %q", i, result)
		}
	}
}

func TestRetryRoundTripperRetriesOnFailure(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts < 3 {
			return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString("done")), Header: make(http.Header)}, nil
	})

	rrt := &retryRoundTripper{base: base, maxAttempts: 3, baseDelay: time.Microsecond}
	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := rrt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected success response, got %d", resp.StatusCode)
	}

	mu.Lock()
	total := attempts
	mu.Unlock()
	if total != 3 {
		t.Fatalf("expected three attempts, got %d", total)
	}
}
