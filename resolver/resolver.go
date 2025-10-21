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
)

type Options struct {
	Server  string
	Timeout time.Duration
}

type Resolver struct {
	resolver *net.Resolver
	timeout  time.Duration
	server   string
}

type Result struct {
	Subdomain   string
	IPAddresses []string
	DNSRecords  map[string][]string
	Err         error
}

func New(options Options) (*Resolver, error) {
	r := &Resolver{timeout: options.Timeout}
	if r.timeout <= 0 {
		r.timeout = 5 * time.Second
	}

	if strings.TrimSpace(options.Server) == "" {
		r.resolver = net.DefaultResolver
		return r, nil
	}

	addr := options.Server
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(strings.TrimSpace(addr), "53")
	}

	dialer := &net.Dialer{}
	r.server = addr
	r.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dctx := ctx
			var cancel context.CancelFunc
			if r.timeout > 0 {
				dctx, cancel = context.WithTimeout(ctx, r.timeout)
			}
			conn, err := dialer.DialContext(dctx, network, addr)
			if cancel != nil {
				cancel()
			}
			return conn, err
		},
	}

	return r, nil
}

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

func (r *Resolver) ResolveAll(ctx context.Context, hostnames []string, workers int) map[string]Result {
	results := make(map[string]Result, len(hostnames))
	if len(hostnames) == 0 {
		return results
	}
	if workers <= 0 {
		workers = 1
	}

	type job struct {
		hostname string
	}

	jobs := make(chan job)
	output := make(chan Result)
	var wg sync.WaitGroup

	startWorker := func() {
		defer wg.Done()
		for j := range jobs {
			output <- r.Resolve(ctx, j.hostname)
		}
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go startWorker()
	}

	go func() {
		for _, hostname := range hostnames {
			hostname = strings.TrimSpace(hostname)
			if hostname == "" {
				continue
			}
			jobs <- job{hostname: hostname}
		}
		close(jobs)
		wg.Wait()
		close(output)
	}()

	for res := range output {
		results[res.Subdomain] = res
	}

	return results
}

func (r *Resolver) lookupIPAddresses(ctx context.Context, hostname string) ([]string, []string, error) {
	resolver := r.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
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

func (r *Resolver) Server() string {
	return r.server
}

func (r *Resolver) Timeout() time.Duration {
	return r.timeout
}

func ParseServer(address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", nil
	}
	if strings.Count(address, ":") == 0 {
		return net.JoinHostPort(address, "53"), nil
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
