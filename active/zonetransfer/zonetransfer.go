package zonetransfer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/yourusername/nitr0g3n/ratelimit"
)

type Options struct {
	Domain      string
	DNSServer   string
	Timeout     time.Duration
	Verbose     bool
	LogWriter   io.Writer
	RateLimiter *ratelimit.Limiter
}

type Result struct {
	Nameserver string
	Records    map[string]map[string][]string
}

func Run(ctx context.Context, opts Options) ([]Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	domain := strings.TrimSpace(strings.ToLower(opts.Domain))
	if domain == "" {
		return nil, errors.New("domain is required")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	server, err := resolveServer(opts.DNSServer)
	if err != nil {
		return nil, err
	}

	client := &dns.Client{Timeout: timeout}

	if opts.RateLimiter != nil {
		if err := opts.RateLimiter.Acquire(ctx); err != nil {
			return nil, err
		}
	}

	nsRecords, err := lookupNS(ctx, client, server, domain)
	if err != nil {
		return nil, err
	}
	if len(nsRecords) == 0 {
		return nil, nil
	}

	transfer := &dns.Transfer{
		DialTimeout: timeout,
		ReadTimeout: timeout,
	}

	results := make([]Result, 0, len(nsRecords))

	for _, ns := range nsRecords {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		if opts.RateLimiter != nil {
			if err := opts.RateLimiter.Acquire(ctx); err != nil {
				return results, err
			}
		}

		addr, err := resolverAddress(ns)
		if err != nil {
			logVerbose(opts, "zone transfer %s: %v", ns, err)
			continue
		}

		request := new(dns.Msg)
		request.SetAxfr(dns.Fqdn(domain))

		records, err := attemptTransfer(transfer, request, addr)
		if err != nil {
			logVerbose(opts, "zone transfer %s failed: %v", ns, err)
			continue
		}
		if len(records) == 0 {
			logVerbose(opts, "zone transfer %s returned no records", ns)
			continue
		}

		results = append(results, Result{
			Nameserver: ns,
			Records:    records,
		})
	}

	return results, nil
}

func lookupNS(ctx context.Context, client *dns.Client, server, domain string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeNS)

	response, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return nil, fmt.Errorf("querying ns records: %w", err)
	}
	if response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("ns query failed with rcode %d", response.Rcode)
	}

	nameservers := make([]string, 0, len(response.Answer))
	for _, rr := range response.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			nameserver := sanitizeName(ns.Ns)
			if nameserver != "" {
				nameservers = append(nameservers, nameserver)
			}
		}
	}

	return uniqueSorted(nameservers), nil
}

func attemptTransfer(transfer *dns.Transfer, msg *dns.Msg, addr string) (map[string]map[string][]string, error) {
	envChan, err := transfer.In(msg, addr)
	if err != nil {
		return nil, err
	}

	records := make(map[string]map[string][]string)
	for env := range envChan {
		if env.Error != nil {
			return nil, env.Error
		}
		for _, rr := range env.RR {
			addRecord(records, rr)
		}
	}

	// ensure determinism for values
	for name, typeRecords := range records {
		for recordType, values := range typeRecords {
			typeRecords[recordType] = uniqueSorted(values)
		}
		records[name] = typeRecords
	}

	return records, nil
}

func addRecord(records map[string]map[string][]string, rr dns.RR) {
	if rr == nil {
		return
	}
	name := sanitizeName(rr.Header().Name)
	if name == "" {
		return
	}

	recordType := dns.TypeToString[rr.Header().Rrtype]
	if recordType == "" {
		recordType = fmt.Sprintf("TYPE%d", rr.Header().Rrtype)
	}

	value := recordValue(rr)
	if value == "" {
		return
	}

	typeRecords := records[name]
	if typeRecords == nil {
		typeRecords = make(map[string][]string)
	}
	typeRecords[recordType] = append(typeRecords[recordType], value)
	records[name] = typeRecords
}

func recordValue(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return sanitizeName(v.Target)
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, sanitizeName(v.Mx))
	case *dns.NS:
		return sanitizeName(v.Ns)
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			sanitizeName(v.Ns), sanitizeName(v.Mbox), v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, sanitizeName(v.Target))
	case *dns.TXT:
		return strings.Join(v.Txt, " ")
	case *dns.CAA:
		return fmt.Sprintf("%d %s %q", v.Flag, v.Tag, v.Value)
	default:
		return strings.TrimSpace(rr.String())
	}
}

func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
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
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func resolveServer(server string) (string, error) {
	server = strings.TrimSpace(server)
	if server != "" {
		if !strings.Contains(server, ":") {
			server = net.JoinHostPort(server, "53")
		}
		return server, nil
	}

	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("loading resolv.conf: %w", err)
	}
	if len(cfg.Servers) == 0 {
		return "", errors.New("no DNS servers configured")
	}

	port := cfg.Port
	if strings.TrimSpace(port) == "" {
		port = "53"
	}

	return net.JoinHostPort(cfg.Servers[0], port), nil
}

func resolverAddress(ns string) (string, error) {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		return "", errors.New("empty nameserver")
	}
	if strings.Contains(ns, ":") {
		return ns, nil
	}
	return net.JoinHostPort(ns, "53"), nil
}

func logVerbose(opts Options, format string, args ...interface{}) {
	if !opts.Verbose || opts.LogWriter == nil {
		return
	}
	fmt.Fprintf(opts.LogWriter, format+"\n", args...)
}
