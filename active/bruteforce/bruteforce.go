package bruteforce

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/yourusername/nitr0g3n/ratelimit"
)

type Options struct {
	Domain         string
	WordlistPath   string
	Permutations   bool
	DNSServer      string
	Timeout        time.Duration
	Workers        int
	ProgressWriter io.Writer
	RateLimiter    *ratelimit.Limiter
}

type Result struct {
	Subdomain string
	Rcode     int
	Answers   []string
}

func Run(ctx context.Context, opts Options) ([]Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	domain := strings.TrimSpace(strings.ToLower(opts.Domain))
	if domain == "" {
		return nil, errors.New("domain is required")
	}

	words, err := loadWords(opts.WordlistPath)
	if err != nil {
		return nil, err
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("wordlist %q produced no entries", opts.WordlistPath)
	}

	labels := buildLabels(words, opts.Permutations)
	if len(labels) == 0 {
		return nil, fmt.Errorf("wordlist %q produced no labels", opts.WordlistPath)
	}

	hostnames := make([]string, 0, len(labels))
	for _, label := range labels {
		hostname := fmt.Sprintf("%s.%s", label, domain)
		hostnames = append(hostnames, hostname)
	}

	server, err := resolveServer(opts.DNSServer)
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = 10
	}

	reporter := newProgressReporter(len(hostnames), opts.ProgressWriter)
	reporter.Start()
	defer reporter.Stop()

	type job struct {
		hostname string
	}

	jobs := make(chan job)
	results := make(chan Result)
	var wg sync.WaitGroup

	queryFunc := func() {
		defer wg.Done()
		client := &dns.Client{Timeout: timeout}
		for j := range jobs {
			if ctx.Err() != nil {
				return
			}

			if opts.RateLimiter != nil {
				if err := opts.RateLimiter.Acquire(ctx); err != nil {
					return
				}
			}

			res, ok := queryHostname(ctx, client, server, j.hostname)
			if ok {
				results <- res
			}
			reporter.Increment()
		}
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go queryFunc()
	}

	go func() {
		defer close(jobs)
		for _, hostname := range hostnames {
			select {
			case <-ctx.Done():
				return
			case jobs <- job{hostname: hostname}:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var found []Result
	seen := make(map[string]struct{})
	for res := range results {
		subdomain := strings.ToLower(strings.TrimSpace(res.Subdomain))
		if subdomain == "" {
			continue
		}
		if _, ok := seen[subdomain]; ok {
			continue
		}
		seen[subdomain] = struct{}{}
		found = append(found, res)
	}

	sort.Slice(found, func(i, j int) bool {
		return found[i].Subdomain < found[j].Subdomain
	})

	return found, nil
}

func loadWords(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		words := DefaultWordlist()
		if len(words) == 0 {
			return nil, errors.New("embedded default wordlist is empty")
		}
		return words, nil
	}

	expanded := path
	if strings.HasPrefix(path, "~") {
		if homeDir, err := os.UserHomeDir(); err == nil {
			remainder := strings.TrimPrefix(path, "~")
			remainder = strings.TrimPrefix(remainder, string(os.PathSeparator))
			expanded = filepath.Join(homeDir, remainder)
		}
	}

	words, err := LoadWordlist(expanded)
	if err != nil {
		return nil, fmt.Errorf("loading wordlist %q: %w", path, err)
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("wordlist %q contained no entries", path)
	}
	return words, nil
}

func buildLabels(words []string, permutations bool) []string {
	seen := make(map[string]struct{}, len(words))
	labels := make([]string, 0, len(words))

	for _, word := range words {
		label := strings.ToLower(strings.TrimSpace(word))
		if label == "" {
			continue
		}

		addLabel := func(candidate string) {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" {
				return
			}
			if _, exists := seen[candidate]; exists {
				return
			}
			seen[candidate] = struct{}{}
			labels = append(labels, candidate)
		}

		addLabel(label)
		if permutations {
			for _, perm := range permutationsFor(label) {
				addLabel(perm)
			}
		}
	}

	return labels
}

func permutationsFor(label string) []string {
	var variants []string
	numbers := numberVariants()
	for _, num := range numbers {
		variants = append(variants,
			label+num,
			num+label,
			label+"-"+num,
			num+"-"+label,
		)
	}
	return variants
}

func numberVariants() []string {
	variants := make([]string, 0, 110)
	for i := 0; i <= 9; i++ {
		variants = append(variants, fmt.Sprintf("%d", i))
	}
	for i := 10; i <= 99; i++ {
		variants = append(variants, fmt.Sprintf("%d", i))
	}
	return variants
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

func queryHostname(ctx context.Context, client *dns.Client, server, hostname string) (Result, bool) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)

	response, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return Result{}, false
	}

	res := Result{
		Subdomain: hostname,
		Rcode:     response.Rcode,
	}

	if response.Rcode != dns.RcodeSuccess {
		return Result{}, false
	}

	answers := extractAnswers(response)
	if len(answers) == 0 {
		return Result{}, false
	}

	res.Answers = answers
	return res, true
}

func extractAnswers(msg *dns.Msg) []string {
	if msg == nil {
		return nil
	}
	answers := make([]string, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			answers = append(answers, v.A.String())
		case *dns.AAAA:
			answers = append(answers, v.AAAA.String())
		case *dns.CNAME:
			answers = append(answers, strings.TrimSuffix(v.Target, "."))
		default:
			answers = append(answers, v.String())
		}
	}
	return answers
}

type progressReporter struct {
	total     int64
	completed int64
	writer    io.Writer
	ticker    *time.Ticker
	done      chan struct{}
}

func newProgressReporter(total int, writer io.Writer) *progressReporter {
	if writer == nil {
		writer = io.Discard
	}
	return &progressReporter{
		total:  int64(total),
		writer: writer,
		done:   make(chan struct{}),
	}
}

func (p *progressReporter) Start() {
	if p.total == 0 || p.writer == io.Discard {
		return
	}
	p.ticker = time.NewTicker(250 * time.Millisecond)
	go func() {
		for {
			select {
			case <-p.ticker.C:
				completed := atomic.LoadInt64(&p.completed)
				percent := 0.0
				if p.total > 0 {
					percent = (float64(completed) / float64(p.total)) * 100
				}
				fmt.Fprintf(p.writer, "\rBruteforcing %d/%d (%.1f%%)", completed, p.total, percent)
			case <-p.done:
				return
			}
		}
	}()
}

func (p *progressReporter) Increment() {
	if p.total == 0 {
		return
	}
	atomic.AddInt64(&p.completed, 1)
}

func (p *progressReporter) Stop() {
	if p.total == 0 || p.writer == io.Discard {
		return
	}
	if p.ticker != nil {
		p.ticker.Stop()
	}
	close(p.done)
	atomic.StoreInt64(&p.completed, p.total)
	fmt.Fprintf(p.writer, "\rBruteforcing %d/%d (100.0%%)\n", p.total, p.total)
}
