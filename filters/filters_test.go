package filters

import (
	"context"
	"sync"
	"testing"

	"github.com/yourusername/nitr0g3n/resolver"
)

type stubResolver struct {
	mu      sync.Mutex
	results []resolver.Result
	calls   int
}

func (s *stubResolver) Resolve(ctx context.Context, host string) resolver.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls >= len(s.results) {
		return resolver.Result{}
	}
	res := s.results[s.calls]
	s.calls++
	return res
}

func TestDetectWildcard(t *testing.T) {
	stub := &stubResolver{results: []resolver.Result{
		{IPAddresses: []string{"192.0.2.1"}},
		{DNSRecords: map[string][]string{"CNAME": []string{"wildcard.example.com"}}},
	}}

	profile, err := DetectWildcard(context.Background(), stub, "example.com", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !profile.Active() {
		t.Fatalf("expected profile to be active")
	}

	match := profile.Matches(resolver.Result{IPAddresses: []string{"192.0.2.1"}})
	if !match {
		t.Fatalf("expected ip match to be true")
	}

	if profile.Matches(resolver.Result{IPAddresses: []string{"198.51.100.1"}}) {
		t.Fatalf("expected mismatch for unknown ip")
	}

	if !profile.Matches(resolver.Result{DNSRecords: map[string][]string{"CNAME": []string{"wildcard.example.com"}}}) {
		t.Fatalf("expected cname match")
	}
}

func TestIsCDNResponse(t *testing.T) {
	if !IsCDNResponse(map[string][]string{"CNAME": []string{"cdn.cloudflare.net"}}) {
		t.Fatalf("expected CDN response to be detected")
	}
	if IsCDNResponse(map[string][]string{"A": []string{"192.0.2.1"}}) {
		t.Fatalf("did not expect CDN detection for plain A record")
	}
}
