package passive

import (
	"context"
	"sort"
	"strings"
	"sync"
)

type Source interface {
	Name() string
	Enumerate(ctx context.Context, domain string) ([]string, error)
}

type AggregateResult struct {
	Subdomains map[string][]string
	Errors     map[string]error
}

type sourceResult struct {
	name       string
	subdomains []string
	err        error
}

func Aggregate(ctx context.Context, domain string, sources []Source) AggregateResult {
	result := AggregateResult{
		Subdomains: make(map[string][]string),
		Errors:     make(map[string]error),
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if strings.TrimSpace(domain) == "" {
		return result
	}

	if len(sources) == 0 {
		return result
	}

	results := make(chan sourceResult, len(sources))
	var wg sync.WaitGroup

	for _, src := range sources {
		if src == nil {
			continue
		}

		wg.Add(1)
		go func(source Source) {
			defer wg.Done()
			subdomains, err := source.Enumerate(ctx, domain)
			results <- sourceResult{
				name:       source.Name(),
				subdomains: subdomains,
				err:        err,
			}
		}(src)
	}

	wg.Wait()
	close(results)

	for res := range results {
		if res.name == "" {
			continue
		}

		if res.err != nil {
			result.Errors[res.name] = res.err
			continue
		}

		for _, subdomain := range res.subdomains {
			subdomain = strings.ToLower(strings.TrimSpace(subdomain))
			if subdomain == "" {
				continue
			}

			sourcesForSubdomain := result.Subdomains[subdomain]
			if !contains(sourcesForSubdomain, res.name) {
				sourcesForSubdomain = append(sourcesForSubdomain, res.name)
				sort.Strings(sourcesForSubdomain)
				result.Subdomains[subdomain] = sourcesForSubdomain
			}
		}
	}

	return result
}

func contains(slice []string, target string) bool {
	for _, item := range slice {
		if item == target {
			return true
		}
	}
	return false
}
