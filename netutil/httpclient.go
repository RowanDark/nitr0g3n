package netutil

import (
	"net"
	"net/http"
	"time"

	"github.com/yourusername/nitr0g3n/ratelimit"
)

type limitingRoundTripper struct {
	base    http.RoundTripper
	limiter *ratelimit.Limiter
}

func (l *limitingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if l == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	base := l.base
	if base == nil {
		base = http.DefaultTransport
	}
	if l.limiter != nil {
		if err := l.limiter.Acquire(req.Context()); err != nil {
			return nil, err
		}
	}
	return base.RoundTrip(req)
}

func NewHTTPClient(timeout time.Duration, limiter *ratelimit.Limiter) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	rt := http.RoundTripper(transport)
	if limiter != nil {
		rt = &limitingRoundTripper{base: rt, limiter: limiter}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: rt,
	}
}
