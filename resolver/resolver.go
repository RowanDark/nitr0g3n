package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RowanDark/nitr0g3n/ratelimit"
)

// dnsResolver captures the subset of the net.Resolver API the package relies on.
type dnsResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	LookupCNAME(context.Context, string) (string, error)
	LookupMX(context.Context, string) ([]*net.MX, error)
	LookupTXT(context.Context, string) ([]string, error)
	LookupNS(context.Context, string) ([]*net.NS, error)
}

// Options controls Resolver instantiation behaviour.
type Options struct {
	Server       string
	Timeout      time.Duration
	RateLimiter  *ratelimit.Limiter
	CacheEnabled bool
	CacheSize    int
}

var defaultDNSServers = []string{
	"8.8.8.8:53",
	"1.1.1.1:53",
	"9.9.9.9:53",
}

// Resolver performs DNS lookups against the system resolver or a custom server.
type Resolver struct {
	resolver dnsResolver
	timeout  time.Duration
	server   string
	limiter  *ratelimit.Limiter
}

// Result summarises the DNS records discovered for a hostname.
type Result struct {
	Subdomain   string
	IPAddresses []string
	DNSRecords  map[string][]string
	Err         error
}

// New instantiates a Resolver using the provided options.
func New(options Options) (*Resolver, error) {
	r := &Resolver{timeout: options.Timeout, limiter: options.RateLimiter}
	if r.timeout <= 0 {
		r.timeout = 5 * time.Second
	}

	servers, err := resolveServers(options.Server)
	if err != nil {
		return nil, err
	}

	cacheSize := options.CacheSize
	if cacheSize <= 0 {
		cacheSize = 10000
	}

	client, err := newDNSClient(dnsClientOptions{
		Servers:      servers,
		Timeout:      r.timeout,
		CacheSize:    cacheSize,
		CacheEnabled: options.CacheEnabled,
	})
	if err != nil {
		return nil, err
	}

	r.resolver = client
	r.server = strings.Join(servers, ",")

	return r, nil
}

// Resolve performs a synchronous DNS lookup for the provided hostname.
func (r *Resolver) Resolve(ctx context.Context, hostname string) Result {
	if ctx == nil {
		ctx = context.Background()
	}

	hostname = strings.TrimSpace(hostname)
	result := Result{
		Subdomain:  hostname,
		DNSRecords: make(map[string][]string),
	}
	if hostname == "" {
		result.Err = fmt.Errorf("empty hostname")
		return result
	}

	var resolutionErrs []string

	aRecords, aaaaRecords, ipsErr := r.lookupIPAddresses(ctx, hostname)
	if ipsErr != nil {
		resolutionErrs = append(resolutionErrs, ipsErr.Error())
	}

	if len(aRecords) > 0 {
		result.DNSRecords["A"] = aRecords
		result.IPAddresses = append(result.IPAddresses, aRecords...)
	}
	if len(aaaaRecords) > 0 {
		result.DNSRecords["AAAA"] = aaaaRecords
		result.IPAddresses = append(result.IPAddresses, aaaaRecords...)
	}

	if cname, err := r.lookupCNAME(ctx, hostname); err == nil && cname != "" {
		result.DNSRecords["CNAME"] = []string{cname}
	} else if err != nil {
		resolutionErrs = append(resolutionErrs, err.Error())
	}

	if mxRecords, err := r.lookupMX(ctx, hostname); err == nil && len(mxRecords) > 0 {
		result.DNSRecords["MX"] = mxRecords
	} else if err != nil {
		resolutionErrs = append(resolutionErrs, err.Error())
	}

	if txtRecords, err := r.lookupTXT(ctx, hostname); err == nil && len(txtRecords) > 0 {
		result.DNSRecords["TXT"] = txtRecords
	} else if err != nil {
		resolutionErrs = append(resolutionErrs, err.Error())
	}

	if nsRecords, err := r.lookupNS(ctx, hostname); err == nil && len(nsRecords) > 0 {
		result.DNSRecords["NS"] = nsRecords
	} else if err != nil {
		resolutionErrs = append(resolutionErrs, err.Error())
	}

	if len(result.IPAddresses) > 0 {
		result.IPAddresses = uniqueSorted(result.IPAddresses)
	}
	if len(result.DNSRecords) > 0 {
		for key := range result.DNSRecords {
			result.DNSRecords[key] = uniqueSorted(result.DNSRecords[key])
		}
	}

	if len(resolutionErrs) > 0 && len(result.IPAddresses) == 0 && len(result.DNSRecords) == 0 {
		result.Err = errors.New(strings.Join(resolutionErrs, "; "))
	}

	return result
}

// ResolveAll launches a worker pool to resolve hostnames concurrently.
func (r *Resolver) ResolveAll(ctx context.Context, hostnames []string, workers int) <-chan Result {
	output := make(chan Result)
	if len(hostnames) == 0 {
		close(output)
		return output
	}
	if workers <= 0 {
		workers = 1
	}

	jobs := make(chan string)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for hostname := range jobs {
			select {
			case <-ctx.Done():
				return
			default:
			}

			res := r.Resolve(ctx, hostname)

			select {
			case output <- res:
			case <-ctx.Done():
				return
			}
		}
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		defer close(jobs)
		for _, hostname := range hostnames {
			hostname = strings.TrimSpace(hostname)
			if hostname == "" {
				continue
			}

			select {
			case <-ctx.Done():
				return
			case jobs <- hostname:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(output)
	}()

	return output
}

// ResolveStream resolves hostnames received over the provided channel. The
// stream closes once the input channel is exhausted and all workers finish.
func (r *Resolver) ResolveStream(ctx context.Context, hostnames <-chan string, workers int) <-chan Result {
	output := make(chan Result)
	if hostnames == nil {
		close(output)
		return output
	}
	if workers <= 0 {
		workers = 1
	}

	jobs := make(chan string)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for hostname := range jobs {
			select {
			case <-ctx.Done():
				return
			default:
			}

			res := r.Resolve(ctx, hostname)

			select {
			case output <- res:
			case <-ctx.Done():
				return
			}
		}
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		defer close(jobs)
		for hostname := range hostnames {
			hostname = strings.TrimSpace(hostname)
			if hostname == "" {
				continue
			}

			select {
			case <-ctx.Done():
				return
			case jobs <- hostname:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(output)
	}()

	return output
}

func (r *Resolver) lookupIPAddresses(ctx context.Context, hostname string) ([]string, []string, error) {
	resolver := r.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	if err := r.acquire(ctx); err != nil {
		return nil, nil, err
	}

	callCtx, cancel := r.withTimeout(ctx)
	defer cancel()

	addrs, err := resolver.LookupIPAddr(callCtx, hostname)
	if err != nil {
		return nil, nil, err
	}

	var aRecords, aaaaRecords []string
	for _, addr := range addrs {
		if addr.IP == nil {
			continue
		}
		if v4 := addr.IP.To4(); v4 != nil {
			aRecords = append(aRecords, v4.String())
		} else {
			aaaaRecords = append(aaaaRecords, addr.IP.String())
		}
	}

	return uniqueSorted(aRecords), uniqueSorted(aaaaRecords), nil
}

func (r *Resolver) lookupCNAME(ctx context.Context, hostname string) (string, error) {
	resolver := r.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	if err := r.acquire(ctx); err != nil {
		return "", err
	}

	callCtx, cancel := r.withTimeout(ctx)
	defer cancel()

	cname, err := resolver.LookupCNAME(callCtx, hostname)
	if err != nil {
		return "", err
	}

	cname = strings.TrimSuffix(cname, ".")
	if strings.EqualFold(cname, hostname) {
		return "", nil
	}

	return cname, nil
}

func (r *Resolver) lookupMX(ctx context.Context, hostname string) ([]string, error) {
	resolver := r.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	if err := r.acquire(ctx); err != nil {
		return nil, err
	}

	callCtx, cancel := r.withTimeout(ctx)
	defer cancel()

	records, err := resolver.LookupMX(callCtx, hostname)
	if err != nil {
		return nil, err
	}

	results := make([]string, 0, len(records))
	for _, record := range records {
		host := strings.TrimSuffix(record.Host, ".")
		results = append(results, fmt.Sprintf("%d %s", record.Pref, host))
	}

	return uniqueSorted(results), nil
}

func (r *Resolver) lookupTXT(ctx context.Context, hostname string) ([]string, error) {
	resolver := r.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	if err := r.acquire(ctx); err != nil {
		return nil, err
	}

	callCtx, cancel := r.withTimeout(ctx)
	defer cancel()

	records, err := resolver.LookupTXT(callCtx, hostname)
	if err != nil {
		return nil, err
	}

	results := make([]string, 0, len(records))
	for _, record := range records {
		results = append(results, record)
	}

	return uniqueSorted(results), nil
}

func (r *Resolver) lookupNS(ctx context.Context, hostname string) ([]string, error) {
	resolver := r.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	if err := r.acquire(ctx); err != nil {
		return nil, err
	}

	callCtx, cancel := r.withTimeout(ctx)
	defer cancel()

	records, err := resolver.LookupNS(callCtx, hostname)
	if err != nil {
		return nil, err
	}

	results := make([]string, 0, len(records))
	for _, record := range records {
		host := strings.TrimSuffix(record.Host, ".")
		results = append(results, host)
	}

	return uniqueSorted(results), nil
}

func (r *Resolver) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if r.timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, r.timeout)
}

func (r *Resolver) acquire(ctx context.Context) error {
	if r.limiter == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return r.limiter.Acquire(ctx)
}

//go:inline
func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// Server returns the configured upstream DNS server address.
//
//go:inline
func (r *Resolver) Server() string {
	return r.server
}

// Timeout returns the configured per-query timeout duration.
//
//go:inline
func (r *Resolver) Timeout() time.Duration {
	return r.timeout
}

// ParseServer normalises DNS server host[:port] strings to host:port form.
//
//go:inline
func ParseServer(address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", nil
	}
	if strings.Count(address, ":") == 0 {
		return net.JoinHostPort(address, "53"), nil
	}
	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
		host := strings.TrimSuffix(strings.TrimPrefix(address, "["), "]")
		if host == "" {
			return "", fmt.Errorf("invalid dns server host")
		}
		return net.JoinHostPort(host, "53"), nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	if port == "" {
		port = "53"
	} else {
		if _, err := strconv.Atoi(port); err != nil {
			return "", fmt.Errorf("invalid dns server port: %w", err)
		}
	}
	return net.JoinHostPort(host, port), nil
}

func resolveServers(custom string) ([]string, error) {
	servers := make([]string, 0, len(defaultDNSServers)+1)
	trimmed := strings.TrimSpace(custom)
	if trimmed != "" {
		parsed, err := ParseServer(trimmed)
		if err != nil {
			return nil, err
		}
		servers = append(servers, parsed)
	}

	for _, candidate := range defaultDNSServers {
		if !containsServer(servers, candidate) {
			servers = append(servers, candidate)
		}
	}

	if len(servers) == 0 {
		servers = append(servers, defaultDNSServers...)
	}

	return servers, nil
}

//go:inline
func containsServer(servers []string, candidate string) bool {
	for _, server := range servers {
		if strings.EqualFold(server, candidate) {
			return true
		}
	}
	return false
}

// resolveServers and containsServer assist with preparing the upstream resolver list.
