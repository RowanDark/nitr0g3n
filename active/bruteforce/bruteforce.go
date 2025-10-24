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

	"github.com/yourusername/nitr0g3n/internal/dnspool"
	"github.com/yourusername/nitr0g3n/internal/intern"
	"github.com/yourusername/nitr0g3n/ratelimit"
)

type Options struct {
	Domain         string
	WordlistPath   string
	Permutations   bool
	DNSServer      string
	Timeout        time.Duration
	Workers        int
	AutoTune       bool
	ProgressWriter io.Writer
	RateLimiter    *ratelimit.Limiter
}

type Result struct {
	Subdomain string
	Rcode     int
	Answers   []string
}

const (
	defaultBatchSize   = 100
	minAutoTuneWorkers = 50
	maxAutoTuneWorkers = 500
)

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
		if label == "" {
			continue
		}
		var builder strings.Builder
		builder.Grow(len(label) + 1 + len(domain))
		builder.WriteString(label)
		builder.WriteByte('.')
		builder.WriteString(domain)
		hostnames = append(hostnames, intern.Intern(builder.String()))
	}

	server, err := resolveServer(opts.DNSServer)
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	reporter := newProgressReporter(len(hostnames), opts.ProgressWriter)
	reporter.Start()
	defer reporter.Stop()

	jobs := make(chan []string)
	results := make(chan Result, 256)
	metrics := make(chan queryMetric, 512)

	pool := newWorkerPool(ctx, workerPoolConfig{
		server:   server,
		timeout:  timeout,
		limiter:  opts.RateLimiter,
		jobs:     jobs,
		results:  results,
		metrics:  metrics,
		reporter: reporter,
	})

	initialWorkers := opts.Workers
	if opts.AutoTune {
		initialWorkers = minAutoTuneWorkers
	}
	if initialWorkers <= 0 {
		initialWorkers = 10
	}
	pool.SetSize(initialWorkers)

	var batchDelay atomic.Int64

	controllerCtx, controllerCancel := context.WithCancel(ctx)
	defer controllerCancel()
	go adaptiveController(controllerCtx, adaptiveControllerConfig{
		autoTune:   opts.AutoTune,
		pool:       pool,
		metrics:    metrics,
		batchDelay: &batchDelay,
	})

	go func() {
		defer close(jobs)
		batch := make([]string, 0, defaultBatchSize)
		for _, hostname := range hostnames {
			if ctx.Err() != nil {
				return
			}

			batch = append(batch, hostname)
			if len(batch) == defaultBatchSize {
				if !dispatchBatch(ctx, jobs, batch, &batchDelay) {
					return
				}
				batch = make([]string, 0, defaultBatchSize)
			}
		}

		if len(batch) > 0 {
			_ = dispatchBatch(ctx, jobs, batch, &batchDelay)
		}
	}()

	go func() {
		pool.Wait()
		close(results)
		close(metrics)
	}()

	estimated := len(hostnames) / 4
	if estimated < 16 {
		estimated = 16
	}
	found := make([]Result, 0, estimated)
	seen := make(map[string]struct{}, len(hostnames))
	for res := range results {
		subdomain := intern.Intern(strings.ToLower(strings.TrimSpace(res.Subdomain)))
		if subdomain == "" {
			continue
		}
		if _, ok := seen[subdomain]; ok {
			continue
		}
		seen[subdomain] = struct{}{}
		res.Subdomain = subdomain
		if len(res.Answers) > 0 {
			for i := range res.Answers {
				res.Answers[i] = intern.Intern(res.Answers[i])
			}
		}
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
			candidate = intern.Intern(candidate)
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

type queryMetric struct {
	duration  time.Duration
	success   bool
	throttled bool
}

func queryHostname(ctx context.Context, client *dns.Client, server, hostname string) (Result, queryMetric, bool) {
	msg := dnspool.AcquireMsg()
	defer dnspool.ReleaseMsg(msg)

	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)

	start := time.Now()
	response, _, err := client.ExchangeContext(ctx, msg, server)
	metric := queryMetric{duration: time.Since(start)}
	if err != nil {
		metric.throttled = isThrottleError(err)
		return Result{}, metric, false
	}

	res := Result{
		Subdomain: intern.Intern(hostname),
		Rcode:     response.Rcode,
	}

	if response.Rcode != dns.RcodeSuccess {
		metric.throttled = isThrottleRcode(response.Rcode)
		return Result{}, metric, false
	}

	answers := extractAnswers(response)
	if len(answers) == 0 {
		return Result{}, metric, false
	}

	res.Answers = answers
	metric.success = true
	return res, metric, true
}

func isThrottleError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if ne, ok := err.(net.Error); ok {
		if ne.Timeout() || ne.Temporary() {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "rate"),
		strings.Contains(msg, "throttle"),
		strings.Contains(msg, "limit"),
		strings.Contains(msg, "refused"),
		strings.Contains(msg, "servfail"):
		return true
	}
	return false
}

func isThrottleRcode(code int) bool {
	switch code {
	case dns.RcodeRefused, dns.RcodeServerFailure, dns.RcodeNotAuth, dns.RcodeNotZone:
		return true
	default:
		return false
	}
}

type workerPoolConfig struct {
	server   string
	timeout  time.Duration
	limiter  *ratelimit.Limiter
	jobs     <-chan []string
	results  chan<- Result
	metrics  chan<- queryMetric
	reporter *progressReporter
}

type workerPool struct {
	ctx     context.Context
	cfg     workerPoolConfig
	mu      sync.Mutex
	cancels []context.CancelFunc
	wg      sync.WaitGroup
}

func newWorkerPool(ctx context.Context, cfg workerPoolConfig) *workerPool {
	if ctx == nil {
		ctx = context.Background()
	}
	return &workerPool{ctx: ctx, cfg: cfg}
}

func (p *workerPool) SetSize(target int) {
	if target < 0 {
		target = 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	current := len(p.cancels)
	switch {
	case target > current:
		for i := current; i < target; i++ {
			p.startWorkerLocked()
		}
	case target < current:
		for current > target {
			cancel := p.cancels[current-1]
			cancel()
			p.cancels = p.cancels[:current-1]
			current--
		}
	}
}

func (p *workerPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.cancels)
}

func (p *workerPool) Wait() {
	p.wg.Wait()
}

func (p *workerPool) startWorkerLocked() {
	workerCtx, cancel := context.WithCancel(p.ctx)
	p.cancels = append(p.cancels, cancel)
	p.wg.Add(1)
	go p.runWorker(workerCtx)
}

func (p *workerPool) runWorker(ctx context.Context) {
	defer p.wg.Done()

	client := &dns.Client{Timeout: p.cfg.timeout}

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.ctx.Done():
			return
		case batch, ok := <-p.cfg.jobs:
			if !ok {
				return
			}
			shouldStop := false
			for _, hostname := range batch {
				if shouldStop {
					break
				}
				select {
				case <-p.ctx.Done():
					return
				default:
				}
				if strings.TrimSpace(hostname) == "" {
					if p.cfg.reporter != nil {
						p.cfg.reporter.Increment()
					}
					continue
				}
				if p.cfg.limiter != nil {
					if err := p.cfg.limiter.Acquire(p.ctx); err != nil {
						return
					}
				}
				res, metric, ok := queryHostname(p.ctx, client, p.cfg.server, hostname)
				if p.cfg.metrics != nil {
					select {
					case p.cfg.metrics <- metric:
					case <-ctx.Done():
						return
					case <-p.ctx.Done():
						return
					}
				}
				if ok {
					select {
					case p.cfg.results <- res:
					case <-ctx.Done():
						return
					case <-p.ctx.Done():
						return
					}
				}
				if p.cfg.reporter != nil {
					p.cfg.reporter.Increment()
				}
				select {
				case <-ctx.Done():
					shouldStop = true
				default:
				}
			}
			if shouldStop {
				return
			}
		}
	}
}

type adaptiveControllerConfig struct {
	autoTune   bool
	pool       *workerPool
	metrics    <-chan queryMetric
	batchDelay *atomic.Int64
}

func adaptiveController(ctx context.Context, cfg adaptiveControllerConfig) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	samples := make([]queryMetric, 0, 512)

	apply := func() {
		if len(samples) == 0 {
			return
		}

		var (
			totalDuration time.Duration
			successCount  int
			throttleCount int
		)
		for _, sample := range samples {
			totalDuration += sample.duration
			if sample.success {
				successCount++
			}
			if sample.throttled {
				throttleCount++
			}
		}

		total := len(samples)
		avgDuration := time.Duration(0)
		if total > 0 {
			avgDuration = totalDuration / time.Duration(total)
		}
		successRate := float64(successCount) / float64(max(1, total))
		throttleRate := float64(throttleCount) / float64(max(1, total))

		// backpressure control via batch delay adjustments
		var desiredDelay time.Duration
		switch {
		case throttleRate > 0.15:
			desiredDelay = 1500 * time.Millisecond
		case throttleRate > 0.08 || avgDuration > 900*time.Millisecond:
			desiredDelay = 750 * time.Millisecond
		case throttleRate > 0 || avgDuration > 600*time.Millisecond:
			desiredDelay = 250 * time.Millisecond
		default:
			desiredDelay = 0
		}
		if cfg.batchDelay != nil {
			current := time.Duration(cfg.batchDelay.Load())
			if current != desiredDelay {
				cfg.batchDelay.Store(int64(desiredDelay))
			}
		}

		if cfg.autoTune && cfg.pool != nil {
			currentWorkers := cfg.pool.Size()
			if currentWorkers == 0 {
				currentWorkers = minAutoTuneWorkers
			}
			desiredWorkers := currentWorkers

			switch {
			case throttleRate > 0.1 || avgDuration > 900*time.Millisecond:
				decrease := currentWorkers - max(5, currentWorkers/4)
				if decrease < minAutoTuneWorkers {
					decrease = minAutoTuneWorkers
				}
				desiredWorkers = decrease
			case throttleRate == 0 && successRate > 0.9 && avgDuration < 400*time.Millisecond:
				increase := currentWorkers + max(5, currentWorkers/5)
				if increase > maxAutoTuneWorkers {
					increase = maxAutoTuneWorkers
				}
				desiredWorkers = increase
			}

			if desiredWorkers != currentWorkers {
				cfg.pool.SetSize(desiredWorkers)
			}
		}

		samples = samples[:0]
	}

	ctxDone := ctx.Done()
	for {
		if ctxDone != nil {
			select {
			case <-ctxDone:
				ctxDone = nil
				cfg.autoTune = false
				if cfg.batchDelay != nil {
					cfg.batchDelay.Store(0)
				}
			default:
			}
		}

		select {
		case metric, ok := <-cfg.metrics:
			if !ok {
				apply()
				return
			}
			samples = append(samples, metric)
		case <-ticker.C:
			apply()
		}
	}
}

func dispatchBatch(ctx context.Context, jobs chan<- []string, batch []string, delay *atomic.Int64) bool {
	if len(batch) == 0 {
		return true
	}
	payload := batch

	for {
		if ctx.Err() != nil {
			return false
		}

		wait := time.Duration(0)
		if delay != nil {
			wait = time.Duration(delay.Load())
		}
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return false
			case <-timer.C:
			}
		}

		select {
		case <-ctx.Done():
			return false
		case jobs <- payload:
			return true
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func extractAnswers(msg *dns.Msg) []string {
	if msg == nil {
		return nil
	}
	answers := make([]string, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			answers = append(answers, intern.Intern(v.A.String()))
		case *dns.AAAA:
			answers = append(answers, intern.Intern(v.AAAA.String()))
		case *dns.CNAME:
			answers = append(answers, intern.Intern(strings.TrimSuffix(v.Target, ".")))
		default:
			answers = append(answers, intern.Intern(v.String()))
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
