package netutil

import (
	"context"
	"errors"
	"net/http"
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
	if _, ok := client.Transport.(*limitingRoundTripper); ok {
		t.Fatalf("expected plain transport when limiter is nil")
	}
}

func TestNewHTTPClientWithLimiter(t *testing.T) {
	limiter := ratelimit.New(1)
	client := NewHTTPClient(5*time.Second, limiter)
	rt, ok := client.Transport.(*limitingRoundTripper)
	if !ok {
		t.Fatalf("expected limiting round tripper")
	}
	if rt.limiter == nil {
		t.Fatalf("expected limiter to be set")
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
