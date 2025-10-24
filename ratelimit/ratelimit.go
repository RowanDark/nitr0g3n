package ratelimit

import (
	"context"
	"math"
	"sync"
	"time"
)

type Limiter struct {
	rate     float64
	capacity float64
	tokens   float64
	lastFill time.Time
	mu       sync.Mutex
}

// Status describes the current utilisation state of a Limiter.
type Status struct {
	Rate        float64
	Capacity    float64
	Remaining   float64
	Utilization float64
	RefillIn    time.Duration
}

func New(rate float64) *Limiter {
	if rate <= 0 {
		return nil
	}
	limiter := &Limiter{
		rate:     rate,
		capacity: math.Max(rate, 1),
		tokens:   math.Max(rate, 1),
		lastFill: time.Now(),
	}
	return limiter
}

func (l *Limiter) Allow() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillLocked(time.Now())
	if l.tokens < 1 {
		return false
	}
	l.tokens -= 1
	return true
}

func (l *Limiter) Acquire(ctx context.Context) error {
	if l == nil {
		return nil
	}
	for {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}

		l.mu.Lock()
		now := time.Now()
		l.refillLocked(now)
		if l.tokens >= 1 {
			l.tokens -= 1
			l.mu.Unlock()
			return nil
		}
		deficit := 1 - l.tokens
		waitSeconds := deficit / l.rate
		waitDuration := time.Duration(waitSeconds * float64(time.Second))
		if waitDuration < time.Millisecond {
			waitDuration = time.Millisecond
		}
		l.mu.Unlock()

		timer := time.NewTimer(waitDuration)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		}
	}
}

func (l *Limiter) refillLocked(now time.Time) {
	if l == nil {
		return
	}
	if now.Before(l.lastFill) {
		l.lastFill = now
		return
	}
	elapsed := now.Sub(l.lastFill)
	if elapsed <= 0 {
		return
	}
	l.tokens += elapsed.Seconds() * l.rate
	if l.tokens > l.capacity {
		l.tokens = l.capacity
	}
	l.lastFill = now
}

// Status returns information about the limiter's current token bucket state.
func (l *Limiter) Status() Status {
	if l == nil {
		return Status{}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.refillLocked(now)

	remaining := l.tokens
	used := l.capacity - remaining
	if used < 0 {
		used = 0
	}

	utilization := 0.0
	if l.capacity > 0 {
		utilization = used / l.capacity
		if utilization < 0 {
			utilization = 0
		}
		if utilization > 1 {
			utilization = 1
		}
	}

	refillIn := time.Duration(0)
	if l.rate > 0 {
		deficit := l.capacity - remaining
		if deficit > 0 {
			refillSeconds := deficit / l.rate
			refillIn = time.Duration(refillSeconds * float64(time.Second))
		}
	}

	return Status{
		Rate:        l.rate,
		Capacity:    l.capacity,
		Remaining:   remaining,
		Utilization: utilization,
		RefillIn:    refillIn,
	}
}
