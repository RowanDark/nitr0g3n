package resolver

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"testing"
	"time"
)

type stubDNSResolver struct {
	ipAddrs []net.IPAddr
	ipErr   error

	cname    string
	cnameErr error

	mxRecords []*net.MX
	mxErr     error

	txtRecords []string
	txtErr     error

	nsRecords []*net.NS
	nsErr     error
}

func (s *stubDNSResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return s.ipAddrs, s.ipErr
}

func (s *stubDNSResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return s.cname, s.cnameErr
}

func (s *stubDNSResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	return s.mxRecords, s.mxErr
}

func (s *stubDNSResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	return s.txtRecords, s.txtErr
}

func (s *stubDNSResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	return s.nsRecords, s.nsErr
}

func TestNewResolverDefaults(t *testing.T) {
	r, err := New(Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedServers := strings.Join(defaultDNSServers, ",")
	if r.Server() != expectedServers {
		t.Fatalf("expected default servers %q, got %q", expectedServers, r.Server())
	}
	if r.Timeout() != 5*time.Second {
		t.Fatalf("expected default timeout, got %s", r.Timeout())
	}
}

func TestNewResolverCustomServer(t *testing.T) {
	r, err := New(Options{Server: "1.1.1.1", Timeout: time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := strings.Join([]string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}, ",")
	if got := r.Server(); got != expected {
		t.Fatalf("expected server list %q, got %q", expected, got)
	}
}

func TestResolveSuccess(t *testing.T) {
	stub := &stubDNSResolver{
		ipAddrs:    []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("2001:db8::1")}},
		cname:      "alias.example.com.",
		mxRecords:  []*net.MX{{Host: "mail.example.com.", Pref: 10}},
		txtRecords: []string{"v=spf1"},
		nsRecords:  []*net.NS{{Host: "ns1.example.com."}},
	}
	r := &Resolver{resolver: stub, timeout: time.Second}

	result := r.Resolve(context.Background(), "www.example.com")
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	expectedIPs := []string{"192.0.2.1", "2001:db8::1"}
	if !equalStringSlices(result.IPAddresses, expectedIPs) {
		t.Fatalf("unexpected IPs: %v", result.IPAddresses)
	}
	if got := result.DNSRecords["CNAME"]; len(got) != 1 || got[0] != "alias.example.com" {
		t.Fatalf("unexpected CNAME: %v", got)
	}
	if got := result.DNSRecords["MX"]; len(got) != 1 || got[0] != "10 mail.example.com" {
		t.Fatalf("unexpected MX: %v", got)
	}
	if got := result.DNSRecords["TXT"]; len(got) != 1 || got[0] != "v=spf1" {
		t.Fatalf("unexpected TXT: %v", got)
	}
	if got := result.DNSRecords["NS"]; len(got) != 1 || got[0] != "ns1.example.com" {
		t.Fatalf("unexpected NS: %v", got)
	}
}

func TestResolveAggregatesErrors(t *testing.T) {
	stub := &stubDNSResolver{
		ipErr:    errors.New("ip lookup failed"),
		cnameErr: errors.New("cname failed"),
		mxErr:    errors.New("mx failed"),
		txtErr:   errors.New("txt failed"),
		nsErr:    errors.New("ns failed"),
	}
	r := &Resolver{resolver: stub}

	result := r.Resolve(context.Background(), "example.com")
	if result.Err == nil {
		t.Fatalf("expected error, got nil")
	}
	if len(result.IPAddresses) != 0 {
		t.Fatalf("expected no IPs, got %v", result.IPAddresses)
	}
}

func TestResolveAll(t *testing.T) {
	stub := &stubDNSResolver{
		ipAddrs: []net.IPAddr{{IP: net.ParseIP("198.51.100.1")}},
	}
	r := &Resolver{resolver: stub}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hostnames := []string{"a.example.com", "b.example.com", ""}
	resultsCh := r.ResolveAll(ctx, hostnames, 2)
	var results []Result
	for res := range resultsCh {
		results = append(results, res)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Subdomain < results[j].Subdomain })
	if results[0].Subdomain != "a.example.com" || results[1].Subdomain != "b.example.com" {
		t.Fatalf("unexpected subdomains: %v", []string{results[0].Subdomain, results[1].Subdomain})
	}
}

func TestParseServer(t *testing.T) {
	tests := map[string]string{
		"8.8.8.8":      "8.8.8.8:53",
		"8.8.8.8:53":   "8.8.8.8:53",
		"[2001::1]":    "[2001::1]:53",
		"[2001::1]:53": "[2001::1]:53",
	}
	for input, expected := range tests {
		got, err := ParseServer(input)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", input, err)
		}
		if got != expected {
			t.Fatalf("expected %q for %q, got %q", expected, input, got)
		}
	}
}

func TestParseServerInvalid(t *testing.T) {
	if _, err := ParseServer("bad::port::value"); err == nil {
		t.Fatalf("expected error for invalid address")
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
