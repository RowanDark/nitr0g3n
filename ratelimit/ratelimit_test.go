package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestLimiterAllow(t *testing.T) {
	limiter := New(1)
	if !limiter.Allow() {
		t.Fatalf("expected first allow to succeed")
	}
	if limiter.Allow() {
		t.Fatalf("expected second allow to be rate limited")
	}
}

func TestLimiterAcquire(t *testing.T) {
	limiter := New(1)
	if err := limiter.Acquire(context.Background()); err != nil {
		t.Fatalf("unexpected error acquiring first token: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := limiter.Acquire(ctx); err == nil {
		t.Fatalf("expected context deadline error when acquiring second token")
	}
}
