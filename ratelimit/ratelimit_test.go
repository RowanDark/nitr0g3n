package ratelimit

import (
	"context"
	"math"
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

func TestLimiterStatus(t *testing.T) {
	limiter := New(5)
	status := limiter.Status()
	if math.Abs(status.Rate-5) > 0.01 {
		t.Fatalf("expected rate to be 5, got %.2f", status.Rate)
	}
	if math.Abs(status.Capacity-5) > 0.01 {
		t.Fatalf("expected capacity to be 5, got %.2f", status.Capacity)
	}
	if math.Abs(status.Remaining-status.Capacity) > 0.01 {
		t.Fatalf("expected remaining tokens to equal capacity, got %.2f", status.Remaining)
	}
	if status.Utilization != 0 {
		t.Fatalf("expected utilization to be 0, got %.2f", status.Utilization)
	}
	if status.RefillIn != 0 {
		t.Fatalf("expected refill duration to be zero, got %s", status.RefillIn)
	}

	if err := limiter.Acquire(context.Background()); err != nil {
		t.Fatalf("unexpected error acquiring token: %v", err)
	}

	status = limiter.Status()
	if math.Abs(status.Remaining-4) > 0.2 {
		t.Fatalf("expected around 4 tokens remaining, got %.2f", status.Remaining)
	}
	if status.Utilization < 0.15 || status.Utilization > 0.25 {
		t.Fatalf("expected utilization around 0.2, got %.2f", status.Utilization)
	}
	if status.RefillIn <= 0 {
		t.Fatalf("expected positive refill duration, got %s", status.RefillIn)
	}
}
