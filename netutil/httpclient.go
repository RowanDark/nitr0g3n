package netutil

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/sync/singleflight"

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
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	_ = http2.ConfigureTransport(transport)

	rt := http.RoundTripper(transport)
	rt = &retryRoundTripper{base: rt, maxAttempts: 3, baseDelay: 200 * time.Millisecond}
	rt = &coalescingRoundTripper{base: rt}
	if limiter != nil {
		rt = &limitingRoundTripper{base: rt, limiter: limiter}
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: rt,
	}
}

type coalescingRoundTripper struct {
	base  http.RoundTripper
	group singleflight.Group
}

func (c *coalescingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if c == nil {
		return http.DefaultTransport.RoundTrip(req)
	}

	base := c.base
	if base == nil {
		base = http.DefaultTransport
	}

	if !isCoalescable(req) {
		return base.RoundTrip(req)
	}

	key := req.Method + " " + req.URL.String()

	type result struct {
		resp *http.Response
		body []byte
	}

	ch := c.group.DoChan(key, func() (interface{}, error) {
		clonedReq, err := cloneRequest(req)
		if err != nil {
			return nil, err
		}
		resp, err := base.RoundTrip(clonedReq)
		if err != nil {
			return nil, err
		}
		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return &result{resp: resp, body: bodyBytes}, nil
	})

	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		data := res.Val.(*result)
		return cloneResponse(data.resp, data.body), nil
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
}

type retryRoundTripper struct {
	base        http.RoundTripper
	maxAttempts int
	baseDelay   time.Duration
}

func (r *retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if r == nil {
		return http.DefaultTransport.RoundTrip(req)
	}

	base := r.base
	if base == nil {
		base = http.DefaultTransport
	}

	attempts := r.maxAttempts
	if attempts <= 0 {
		attempts = 1
	}

	if !hasReplayableBody(req) {
		return base.RoundTrip(req)
	}

	var lastErr error
	var lastResp *http.Response

	for attempt := 0; attempt < attempts; attempt++ {
		if lastResp != nil {
			lastResp.Body.Close()
			lastResp = nil
		}

		currentReq := req
		if attempt > 0 {
			var err error
			currentReq, err = cloneRequest(req)
			if err != nil {
				return nil, err
			}
		}

		resp, err := base.RoundTrip(currentReq)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}

		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("http status %s", resp.Status)
			lastResp = resp
		}

		if attempt == attempts-1 {
			break
		}

		if lastResp != nil {
			lastResp.Body.Close()
			lastResp = nil
		}

		backoff := r.baseDelay
		if backoff <= 0 {
			backoff = 200 * time.Millisecond
		}
		backoff = backoff << attempt

		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-req.Context().Done():
			timer.Stop()
			return nil, req.Context().Err()
		}
	}

	if lastResp != nil {
		return lastResp, nil
	}

	return nil, lastErr
}

func isCoalescable(req *http.Request) bool {
	if !hasReplayableBody(req) {
		return false
	}
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		return true
	default:
		return false
	}
}

func cloneRequest(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())
	if req.Body == nil || req.Body == http.NoBody {
		clone.Body = http.NoBody
		return clone, nil
	}
	if req.GetBody == nil {
		return nil, fmt.Errorf("request body is not replayable")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	clone.Body = body
	return clone, nil
}

func cloneResponse(resp *http.Response, body []byte) *http.Response {
	if resp == nil {
		return nil
	}
	clone := new(http.Response)
	*clone = *resp
	clone.Header = resp.Header.Clone()
	if resp.Trailer != nil {
		clone.Trailer = resp.Trailer.Clone()
	}
	if resp.TransferEncoding != nil {
		clone.TransferEncoding = append([]string(nil), resp.TransferEncoding...)
	}
	clone.Body = io.NopCloser(bytes.NewReader(body))
	clone.ContentLength = int64(len(body))
	return clone
}

func hasReplayableBody(req *http.Request) bool {
	if req.Body == nil || req.Body == http.NoBody {
		return true
	}
	return req.GetBody != nil
}
