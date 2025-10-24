package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type dnsClientOptions struct {
	Servers      []string
	Timeout      time.Duration
	CacheEnabled bool
	CacheSize    int
}

type dnsClient struct {
	client       *dns.Client
	servers      []string
	timeout      time.Duration
	cacheEnabled bool
	cache        *DNSCache

	poolMu    sync.Mutex
	connPools map[string]chan *dns.Conn
	poolSize  int
}

func newDNSClient(opts dnsClientOptions) (*dnsClient, error) {
	if len(opts.Servers) == 0 {
		return nil, fmt.Errorf("at least one DNS server must be configured")
	}

	poolSize := 64
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	client := &dns.Client{
		Net:            "udp",
		Timeout:        timeout,
		Dialer:         &net.Dialer{Timeout: timeout},
		ReadTimeout:    timeout,
		WriteTimeout:   timeout,
		SingleInflight: true,
	}

	var cache *DNSCache
	cacheEnabled := opts.CacheEnabled && opts.CacheSize > 0
	if cacheEnabled {
		cache = newDNSCache(opts.CacheSize)
	}

	return &dnsClient{
		client:       client,
		servers:      append([]string(nil), opts.Servers...),
		timeout:      timeout,
		cacheEnabled: cacheEnabled,
		cache:        cache,
		connPools:    make(map[string]chan *dns.Conn),
		poolSize:     poolSize,
	}, nil
}

func (c *dnsClient) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	normalized := normalizeHost(host)
	if normalized == "" {
		return nil, fmt.Errorf("empty hostname")
	}

	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
	cached := make(map[uint16][]dns.RR, len(qtypes))
	missing := make([]uint16, 0, len(qtypes))

	for _, qt := range qtypes {
		if recs, ok := c.getCached(normalized, qt); ok {
			cached[qt] = recs
			continue
		}
		missing = append(missing, qt)
	}

	var lookupErr error
	if len(missing) > 0 {
		results, err := c.multiQuery(ctx, normalized, missing)
		if err != nil {
			lookupErr = err
		} else {
			for qt, res := range results {
				cached[qt] = res.records
				if len(res.records) > 0 {
					c.storeCache(normalized, qt, res.records, res.ttl)
				}
			}
		}
	}

	ips := make([]net.IPAddr, 0)
	for _, qt := range qtypes {
		for _, rr := range cached[qt] {
			switch v := rr.(type) {
			case *dns.A:
				ip := make(net.IP, len(v.A))
				copy(ip, v.A)
				ips = append(ips, net.IPAddr{IP: ip})
			case *dns.AAAA:
				ip := make(net.IP, len(v.AAAA))
				copy(ip, v.AAAA)
				ips = append(ips, net.IPAddr{IP: ip})
			}
		}
	}

	if len(ips) == 0 {
		if lookupErr != nil {
			return nil, lookupErr
		}
		return nil, fmt.Errorf("no such host")
	}

	return ips, nil
}

func (c *dnsClient) LookupCNAME(ctx context.Context, host string) (string, error) {
	normalized := normalizeHost(host)
	if normalized == "" {
		return "", fmt.Errorf("empty hostname")
	}

	records, ttl, err := c.fetchRecords(ctx, normalized, dns.TypeCNAME)
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "", nil
	}

	cname, ok := records[0].(*dns.CNAME)
	if !ok {
		return "", nil
	}

	if ttl > 0 {
		c.storeCache(normalized, dns.TypeCNAME, records, ttl)
	}

	target := strings.TrimSuffix(cname.Target, ".")
	if target == "" || strings.EqualFold(target, normalized) {
		return "", nil
	}

	return target, nil
}

func (c *dnsClient) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	normalized := normalizeHost(host)
	if normalized == "" {
		return nil, fmt.Errorf("empty hostname")
	}

	records, ttl, err := c.fetchRecords(ctx, normalized, dns.TypeMX)
	if err != nil {
		return nil, err
	}

	mxRecords := make([]*net.MX, 0, len(records))
	for _, rr := range records {
		if mx, ok := rr.(*dns.MX); ok {
			mxRecords = append(mxRecords, &net.MX{Host: strings.TrimSuffix(mx.Mx, "."), Pref: mx.Preference})
		}
	}

	if len(mxRecords) > 0 && ttl > 0 {
		c.storeCache(normalized, dns.TypeMX, records, ttl)
	}

	if len(mxRecords) == 0 {
		return nil, fmt.Errorf("no such host")
	}

	return mxRecords, nil
}

func (c *dnsClient) LookupTXT(ctx context.Context, host string) ([]string, error) {
	normalized := normalizeHost(host)
	if normalized == "" {
		return nil, fmt.Errorf("empty hostname")
	}

	records, ttl, err := c.fetchRecords(ctx, normalized, dns.TypeTXT)
	if err != nil {
		return nil, err
	}

	values := make([]string, 0, len(records))
	for _, rr := range records {
		if txt, ok := rr.(*dns.TXT); ok {
			values = append(values, strings.Join(txt.Txt, ""))
		}
	}

	if len(values) > 0 && ttl > 0 {
		c.storeCache(normalized, dns.TypeTXT, records, ttl)
	}

	if len(values) == 0 {
		return nil, fmt.Errorf("no such host")
	}

	return values, nil
}

func (c *dnsClient) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	normalized := normalizeHost(host)
	if normalized == "" {
		return nil, fmt.Errorf("empty hostname")
	}

	records, ttl, err := c.fetchRecords(ctx, normalized, dns.TypeNS)
	if err != nil {
		return nil, err
	}

	nsRecords := make([]*net.NS, 0, len(records))
	for _, rr := range records {
		if ns, ok := rr.(*dns.NS); ok {
			nsRecords = append(nsRecords, &net.NS{Host: strings.TrimSuffix(ns.Ns, ".")})
		}
	}

	if len(nsRecords) > 0 && ttl > 0 {
		c.storeCache(normalized, dns.TypeNS, records, ttl)
	}

	if len(nsRecords) == 0 {
		return nil, fmt.Errorf("no such host")
	}

	return nsRecords, nil
}

func (c *dnsClient) fetchRecords(ctx context.Context, host string, qtype uint16) ([]dns.RR, time.Duration, error) {
	if records, ok := c.getCached(host, qtype); ok {
		return records, 0, nil
	}

	records, ttl, err := c.query(ctx, host, qtype)
	if err != nil {
		return nil, 0, err
	}

	return records, ttl, nil
}

func (c *dnsClient) getCached(host string, qtype uint16) ([]dns.RR, bool) {
	if !c.cacheEnabled || c.cache == nil {
		return nil, false
	}
	return c.cache.Get(host, qtype)
}

func (c *dnsClient) storeCache(host string, qtype uint16, records []dns.RR, ttl time.Duration) {
	if !c.cacheEnabled || c.cache == nil || ttl <= 0 || len(records) == 0 {
		return
	}
	c.cache.Set(host, qtype, records, ttl)
}

func (c *dnsClient) query(ctx context.Context, host string, qtype uint16) ([]dns.RR, time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		records []dns.RR
		ttl     time.Duration
		err     error
	}

	responses := make(chan result, len(c.servers))
	var wg sync.WaitGroup

	for _, server := range c.servers {
		server := server
		wg.Add(1)
		go func() {
			defer wg.Done()
			recs, ttls, err := c.queryServerMulti(ctx, server, host, []uint16{qtype})
			if err != nil {
				select {
				case responses <- result{err: err}:
				case <-ctx.Done():
				}
				return
			}
			select {
			case responses <- result{records: recs[qtype], ttl: ttls[qtype]}:
			case <-ctx.Done():
			}
		}()
	}

	go func() {
		wg.Wait()
		close(responses)
	}()

	var combinedErr error
	for res := range responses {
		if res.err == nil {
			cancel()
			return res.records, res.ttl, nil
		}
		combinedErr = combineErrors(combinedErr, res.err)
	}

	if combinedErr == nil {
		combinedErr = fmt.Errorf("no dns response for %s", host)
	}

	return nil, 0, combinedErr
}

func (c *dnsClient) multiQuery(ctx context.Context, host string, qtypes []uint16) (map[uint16]queryRecords, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type multiResult struct {
		records map[uint16][]dns.RR
		ttls    map[uint16]time.Duration
		err     error
	}

	responses := make(chan multiResult, len(c.servers))
	var wg sync.WaitGroup

	for _, server := range c.servers {
		server := server
		wg.Add(1)
		go func() {
			defer wg.Done()
			recs, ttls, err := c.queryServerMulti(ctx, server, host, qtypes)
			select {
			case responses <- multiResult{records: recs, ttls: ttls, err: err}:
			case <-ctx.Done():
			}
		}()
	}

	go func() {
		wg.Wait()
		close(responses)
	}()

	var combinedErr error
	for res := range responses {
		if res.err == nil {
			cancel()
			output := make(map[uint16]queryRecords, len(res.records))
			for qt, records := range res.records {
				output[qt] = queryRecords{records: records, ttl: res.ttls[qt]}
			}
			return output, nil
		}
		combinedErr = combineErrors(combinedErr, res.err)
	}

	if combinedErr == nil {
		combinedErr = fmt.Errorf("no dns response for %s", host)
	}

	return nil, combinedErr
}

type queryRecords struct {
	records []dns.RR
	ttl     time.Duration
}

func (c *dnsClient) queryServerMulti(ctx context.Context, server, host string, qtypes []uint16) (map[uint16][]dns.RR, map[uint16]time.Duration, error) {
	conn, err := c.getConn(ctx, server)
	if err != nil {
		return nil, nil, err
	}

	success := false
	defer func() {
		if success {
			c.putConn(server, conn)
		} else {
			_ = conn.Close()
		}
	}()

	fqdn := dns.Fqdn(host)
	answers := make(map[uint16][]dns.RR, len(qtypes))
	ttls := make(map[uint16]time.Duration, len(qtypes))

	for _, qt := range qtypes {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		msg := new(dns.Msg)
		msg.SetQuestion(fqdn, qt)
		msg.RecursionDesired = true

		resp, err := c.exchange(ctx, conn, msg)
		if err != nil {
			return nil, nil, err
		}
		if resp.Rcode != dns.RcodeSuccess {
			return nil, nil, fmt.Errorf("%s lookup failed with %s", dns.TypeToString[qt], dns.RcodeToString[resp.Rcode])
		}

		filtered := filterRecords(resp.Answer, qt)
		answers[qt] = filtered
		ttls[qt] = extractTTL(filtered)
	}

	success = true
	return answers, ttls, nil
}

func (c *dnsClient) exchange(ctx context.Context, conn *dns.Conn, msg *dns.Msg) (*dns.Msg, error) {
	deadline := time.Time{}
	if ctx != nil {
		if d, ok := ctx.Deadline(); ok {
			deadline = d
		}
	}
	if deadline.IsZero() && c.timeout > 0 {
		deadline = time.Now().Add(c.timeout)
	}
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	resp, _, err := c.client.ExchangeWithConn(msg, conn)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *dnsClient) getConn(ctx context.Context, server string) (*dns.Conn, error) {
	pool := c.getPool(server)
	select {
	case conn := <-pool:
		return conn, nil
	default:
	}

	if ctx == nil {
		ctx = context.Background()
	}
	return c.client.DialContext(ctx, server)
}

func (c *dnsClient) putConn(server string, conn *dns.Conn) {
	if conn == nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	pool := c.getPool(server)
	select {
	case pool <- conn:
	default:
		_ = conn.Close()
	}
}

func (c *dnsClient) getPool(server string) chan *dns.Conn {
	c.poolMu.Lock()
	defer c.poolMu.Unlock()
	if pool, ok := c.connPools[server]; ok {
		return pool
	}
	pool := make(chan *dns.Conn, c.poolSize)
	c.connPools[server] = pool
	return pool
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	fqdn := dns.Fqdn(host)
	return strings.TrimSuffix(strings.ToLower(fqdn), ".")
}

func filterRecords(records []dns.RR, qtype uint16) []dns.RR {
	filtered := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		if rr == nil {
			continue
		}
		if rr.Header().Rrtype != qtype {
			continue
		}
		filtered = append(filtered, dns.Copy(rr))
	}
	return filtered
}

func extractTTL(records []dns.RR) time.Duration {
	if len(records) == 0 {
		return 0
	}
	min := records[0].Header().Ttl
	for _, rr := range records[1:] {
		if rr.Header().Ttl < min {
			min = rr.Header().Ttl
		}
	}
	if min == 0 {
		return 0
	}
	return time.Duration(min) * time.Second
}

func combineErrors(existing, next error) error {
	if existing == nil {
		return next
	}
	if next == nil {
		return existing
	}
	return fmt.Errorf("%v; %w", existing, next)
}

type DNSCache struct {
	mu         sync.RWMutex
	entries    map[string]*CacheEntry
	maxEntries int
}

type CacheEntry struct {
	records []dns.RR
	expiry  time.Time
}

func newDNSCache(size int) *DNSCache {
	if size <= 0 {
		size = 1
	}
	return &DNSCache{
		entries:    make(map[string]*CacheEntry, size),
		maxEntries: size,
	}
}

func (c *DNSCache) Get(host string, qtype uint16) ([]dns.RR, bool) {
	if c == nil {
		return nil, false
	}
	key := cacheKey(host, qtype)
	now := time.Now()

	c.mu.RLock()
	entry, ok := c.entries[key]
	if !ok {
		c.mu.RUnlock()
		return nil, false
	}
	if now.After(entry.expiry) {
		c.mu.RUnlock()
		c.mu.Lock()
		if current, ok := c.entries[key]; ok && now.After(current.expiry) {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		return nil, false
	}
	records := cloneRecords(entry.records)
	c.mu.RUnlock()
	return records, true
}

func (c *DNSCache) Set(host string, qtype uint16, records []dns.RR, ttl time.Duration) {
	if c == nil || ttl <= 0 || len(records) == 0 {
		return
	}
	if ttl < time.Second {
		ttl = time.Second
	}
	key := cacheKey(host, qtype)
	entry := &CacheEntry{
		records: cloneRecords(records),
		expiry:  time.Now().Add(ttl),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxEntries {
		c.evictExpiredLocked()
		if len(c.entries) >= c.maxEntries {
			c.evictOneLocked()
		}
	}

	c.entries[key] = entry
}

func (c *DNSCache) evictExpiredLocked() {
	if c == nil {
		return
	}
	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiry) {
			delete(c.entries, key)
		}
	}
}

func (c *DNSCache) evictOneLocked() {
	for key := range c.entries {
		delete(c.entries, key)
		break
	}
}

func cloneRecords(records []dns.RR) []dns.RR {
	cloned := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		if rr == nil {
			continue
		}
		cloned = append(cloned, dns.Copy(rr))
	}
	return cloned
}

func cacheKey(host string, qtype uint16) string {
	return fmt.Sprintf("%s|%d", host, qtype)
}
