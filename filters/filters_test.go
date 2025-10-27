package filters

import (
	"context"
	"sync"
	"testing"

	"github.com/RowanDark/nitr0g3n/resolver"
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
	resetWildcardCache()
	stub := &stubResolver{results: []resolver.Result{
		{IPAddresses: []string{"192.0.2.1"}},
		{DNSRecords: map[string][]string{"CNAME": []string{"wildcard.example.com"}}},
		{IPAddresses: []string{"192.0.2.2"}},
	}}

	profile, err := DetectWildcard(context.Background(), stub, "example.com", 3, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !profile.Active() {
		t.Fatalf("expected profile to be active")
	}

	if !profile.Matches(resolver.Result{IPAddresses: []string{"192.0.2.1"}}) {
		t.Fatalf("expected ip match to be true")
	}

	if profile.Matches(resolver.Result{IPAddresses: []string{"198.51.100.1"}}) {
		t.Fatalf("expected mismatch for unknown ip")
	}

	if !profile.Matches(resolver.Result{DNSRecords: map[string][]string{"CNAME": []string{"wildcard.example.com"}}}) {
		t.Fatalf("expected cname match")
	}
}

func TestWildcardProfileFuzzyMatch(t *testing.T) {
	resetWildcardCache()
	stub := &stubResolver{results: []resolver.Result{
		{IPAddresses: []string{"203.0.113.10"}},
		{IPAddresses: []string{"203.0.113.200"}},
		{IPAddresses: []string{"2001:db8::1"}},
	}}

	profile, err := DetectWildcard(context.Background(), stub, "example.com", 3, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !profile.Active() {
		t.Fatalf("expected profile to be active")
	}

	if !profile.Matches(resolver.Result{IPAddresses: []string{"203.0.113.55"}}) {
		t.Fatalf("expected fuzzy IPv4 match in shared /24")
	}
	if !profile.Matches(resolver.Result{IPAddresses: []string{"2001:db8::abcd"}}) {
		t.Fatalf("expected fuzzy IPv6 match in shared /64")
	}
	if profile.Matches(resolver.Result{IPAddresses: []string{"198.51.100.1"}}) {
		t.Fatalf("did not expect match for unrelated IP range")
	}
}

func TestDetectWildcardCache(t *testing.T) {
	resetWildcardCache()
	stub := &stubResolver{results: []resolver.Result{
		{IPAddresses: []string{"192.0.2.1"}},
		{IPAddresses: []string{"192.0.2.2"}},
		{IPAddresses: []string{"192.0.2.3"}},
	}}

	if _, err := DetectWildcard(context.Background(), stub, "cache.example", 3, 3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	calls := stub.calls
	if calls == 0 {
		t.Fatalf("expected resolver to be queried")
	}

	if _, err := DetectWildcard(context.Background(), stub, "cache.example", 3, 3); err != nil {
		t.Fatalf("unexpected error on cached detection: %v", err)
	}
	if stub.calls != calls {
		t.Fatalf("expected cached result to avoid new queries, got %d -> %d", calls, stub.calls)
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
