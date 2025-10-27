package filters

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yourusername/nitr0g3n/resolver"
)

// DNSResolver captures the subset of resolver.Resolver required for wildcard detection.
type DNSResolver interface {
	Resolve(context.Context, string) resolver.Result
}

// WildcardProfile represents the DNS records observed for wildcard responses.
type WildcardProfile struct {
	active       bool
	ips          map[string]struct{}
	ipv4Prefixes map[string]struct{}
	ipv6Prefixes map[string]struct{}
	cnames       map[string]struct{}
}

var wildcardCache sync.Map

// DetectWildcard probes random subdomains to identify wildcard DNS behaviour.
func DetectWildcard(ctx context.Context, r DNSResolver, domain string, samples, batch int) (WildcardProfile, error) {
	profile := WildcardProfile{}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if r == nil || domain == "" {
		return profile, nil
	}

	if cached, ok := wildcardCache.Load(domain); ok {
		return cached.(WildcardProfile), nil
	}

	if samples < 3 {
		samples = 3
	} else if samples > 5 {
		samples = 5
	}
	if batch <= 0 {
		batch = samples
	}
	if batch > samples {
		batch = samples
	}

	ips := make(map[string]struct{})
	ipv4Prefixes := make(map[string]struct{})
	ipv6Prefixes := make(map[string]struct{})
	cnames := make(map[string]struct{})

	results := make(chan resolver.Result, samples)
	var wg sync.WaitGroup
	sem := make(chan struct{}, batch)

	launchQuery := func() {
		defer wg.Done()
		hostname := randomLabel() + "." + domain
		res := r.Resolve(ctx, hostname)
		if len(res.IPAddresses) == 0 && len(res.DNSRecords) == 0 {
			return
		}
		results <- res
	}

Loop:
	for i := 0; i < samples; i++ {
		if ctx != nil {
			select {
			case <-ctx.Done():
				break Loop
			default:
			}
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			launchQuery()
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	successCount := 0
	for res := range results {
		successCount++
		for _, ip := range res.IPAddresses {
			trimmed := strings.TrimSpace(ip)
			if trimmed == "" {
				continue
			}
			ips[trimmed] = struct{}{}
			if prefix := ipv4Prefix(trimmed); prefix != "" {
				ipv4Prefixes[prefix] = struct{}{}
			}
			if prefix := ipv6Prefix(trimmed); prefix != "" {
				ipv6Prefixes[prefix] = struct{}{}
			}
		}
		if cn, ok := res.DNSRecords["CNAME"]; ok {
			for _, value := range cn {
				cleaned := strings.ToLower(strings.TrimSpace(value))
				if cleaned == "" {
					continue
				}
				cnames[cleaned] = struct{}{}
			}
		}
	}

	if successCount == 0 {
		wildcardCache.Store(domain, profile)
		return profile, nil
	}

	profile.active = true
	profile.ips = ips
	profile.ipv4Prefixes = ipv4Prefixes
	profile.ipv6Prefixes = ipv6Prefixes
	profile.cnames = cnames

	wildcardCache.Store(domain, profile)
	return profile, nil
}

// Active indicates whether the profile captured successful wildcard responses.
//
//go:inline
func (p WildcardProfile) Active() bool {
	return p.active
}

// Matches reports whether the provided DNS result aligns with the wildcard profile.
//
//go:inline
func (p WildcardProfile) Matches(res resolver.Result) bool {
	if !p.Active() {
		return false
	}
	if len(p.ips) == 0 && len(p.cnames) == 0 && len(p.ipv4Prefixes) == 0 && len(p.ipv6Prefixes) == 0 {
		return false
	}

	if len(p.ips) > 0 || len(p.ipv4Prefixes) > 0 || len(p.ipv6Prefixes) > 0 {
		for _, ip := range res.IPAddresses {
			trimmed := strings.TrimSpace(ip)
			if trimmed == "" {
				continue
			}
			if _, ok := p.ips[trimmed]; ok {
				return true
			}
			if prefix := ipv4Prefix(trimmed); prefix != "" {
				if _, ok := p.ipv4Prefixes[prefix]; ok {
					return true
				}
			}
			if prefix := ipv6Prefix(trimmed); prefix != "" {
				if _, ok := p.ipv6Prefixes[prefix]; ok {
					return true
				}
			}
		}
	}

	if len(p.cnames) > 0 {
		cnames := res.DNSRecords["CNAME"]
		if len(cnames) > 0 {
			for _, cname := range cnames {
				if _, ok := p.cnames[strings.ToLower(strings.TrimSpace(cname))]; ok {
					return true
				}
			}
		}
	}

	return false
}

// IsCDNResponse heuristically determines if DNS records likely point to a CDN.
//
//go:inline
func IsCDNResponse(records map[string][]string) bool {
	if len(records) == 0 {
		return false
	}

	known := []string{
		"cloudflare",
		"cloudfront",
		"akamai",
		"edgesuite",
		"akamaiedge",
		"fastly",
		"cdn77",
		"cdn.cloudflare",
		"azureedge",
		"azurefd",
		"trafficmanager.net",
		"amazonaws.com",
		"cloudapp.net",
		"googleusercontent.com",
		"cdngc.net",
	}

	lowerRecords := make([]string, 0)
	for recordType, values := range records {
		if recordType != "CNAME" && recordType != "TXT" {
			continue
		}
		for _, value := range values {
			lowerRecords = append(lowerRecords, strings.ToLower(value))
		}
	}

	if len(lowerRecords) == 0 {
		return false
	}

	for _, value := range lowerRecords {
		for _, needle := range known {
			if strings.Contains(value, needle) {
				return true
			}
		}
	}

	return false
}

//go:inline
func randomLabel() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return strings.ToLower(time.Now().UTC().Format("150405"))
	}
	return hex.EncodeToString(buf)
}

func ipv4Prefix(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	v4 := parsed.To4()
	if v4 == nil {
		return ""
	}
	return strings.Join([]string{strconv.Itoa(int(v4[0])), strconv.Itoa(int(v4[1])), strconv.Itoa(int(v4[2]))}, ".")
}

func ipv6Prefix(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if parsed.To4() != nil {
		return ""
	}
	parsed = parsed.To16()
	if parsed == nil {
		return ""
	}
	return hex.EncodeToString(parsed[:8])
}

func resetWildcardCache() {
	wildcardCache = sync.Map{}
}
