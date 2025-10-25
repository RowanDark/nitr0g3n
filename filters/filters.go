package filters

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/yourusername/nitr0g3n/resolver"
)

// DNSResolver captures the subset of resolver.Resolver required for wildcard detection.
type DNSResolver interface {
	Resolve(context.Context, string) resolver.Result
}

// WildcardProfile represents the DNS records observed for wildcard responses.
type WildcardProfile struct {
	active bool
	ips    map[string]struct{}
	cnames map[string]struct{}
}

// DetectWildcard probes random subdomains to identify wildcard DNS behaviour.
func DetectWildcard(ctx context.Context, r DNSResolver, domain string, samples int) (WildcardProfile, error) {
	profile := WildcardProfile{}
	if r == nil || strings.TrimSpace(domain) == "" {
		return profile, nil
	}
	if samples <= 0 {
		samples = 3
	}

	ips := make(map[string]struct{})
	cnames := make(map[string]struct{})
	successCount := 0

	for i := 0; i < samples; i++ {
		hostname := randomLabel() + "." + domain
		res := r.Resolve(ctx, hostname)
		if len(res.IPAddresses) == 0 && len(res.DNSRecords) == 0 {
			continue
		}
		successCount++
		for _, ip := range res.IPAddresses {
			ips[strings.TrimSpace(ip)] = struct{}{}
		}
		if cn, ok := res.DNSRecords["CNAME"]; ok {
			for _, value := range cn {
				cnames[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
			}
		}
	}

	if successCount == 0 {
		return profile, nil
	}

	profile.active = true
	profile.ips = ips
	profile.cnames = cnames
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
	if len(p.ips) == 0 && len(p.cnames) == 0 {
		return false
	}

	if len(p.ips) > 0 {
		matched := true
		for _, ip := range res.IPAddresses {
			if _, ok := p.ips[strings.TrimSpace(ip)]; !ok {
				matched = false
				break
			}
		}
		if matched && len(res.IPAddresses) > 0 {
			return true
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
