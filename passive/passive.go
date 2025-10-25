package passive

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// Source defines the contract implemented by passive intelligence providers.
type Source interface {
	Name() string
	Enumerate(ctx context.Context, domain string) ([]string, error)
}

// AggregateResult captures the merged results from all passive sources.
type AggregateResult struct {
	Subdomains map[string][]string
	Errors     map[string]error
}

// Event represents a single update emitted while aggregating passive results.
type Event struct {
	Source    string
	Subdomain string
	Err       error
	New       bool
}

// Options controls AggregateStream runtime behaviour.
type Options struct {
	Parallel      bool
	SourceTimeout time.Duration
}

const defaultSourceTimeout = 30 * time.Second

// Aggregate queries all provided passive sources and merges their output.
// It blocks until all sources have completed and no streaming is performed.
func Aggregate(ctx context.Context, domain string, sources []Source) AggregateResult {
	events, wait := AggregateStream(ctx, domain, sources, Options{Parallel: true})
	for range events {
		// Drain the stream to ensure all goroutines complete before waiting.
	}
	return wait()
}

// AggregateStream queries passive sources and streams results as they arrive.
// A channel of Event values is returned immediately. Consumers must read from
// the channel until it closes, then invoke the returned wait function to obtain
// the final aggregate result.
func AggregateStream(ctx context.Context, domain string, sources []Source, options Options) (<-chan Event, func() AggregateResult) {
	if ctx == nil {
		ctx = context.Background()
	}

	domain = strings.TrimSpace(domain)
	events := make(chan Event, len(sources))

	if domain == "" || len(sources) == 0 {
		close(events)
		return events, func() AggregateResult {
			return AggregateResult{
				Subdomains: make(map[string][]string),
				Errors:     make(map[string]error),
			}
		}
	}

	agg := &aggregator{
		ctx:      ctx,
		domain:   domain,
		sources:  sources,
		options:  options,
		events:   events,
		seen:     sync.Map{},
		errors:   sync.Map{},
		waitOnce: sync.Once{},
	}

	go agg.run()

	waitFn := func() AggregateResult {
		return agg.wait()
	}

	return events, waitFn
}

type aggregator struct {
	ctx     context.Context
	domain  string
	sources []Source
	options Options

	events chan Event

	seen   sync.Map // subdomain -> *sync.Map of sources
	errors sync.Map // source -> error

	wg       sync.WaitGroup
	waitOnce sync.Once
}

func (a *aggregator) run() {
	defer close(a.events)

	timeout := a.options.SourceTimeout
	if timeout <= 0 {
		timeout = defaultSourceTimeout
	}

	launch := func(src Source) {
		if src == nil {
			return
		}
		a.wg.Add(1)
		go a.enumerate(src, timeout)
	}

	if a.options.Parallel {
		for _, src := range a.sources {
			launch(src)
		}
	} else {
		for _, src := range a.sources {
			if src == nil {
				continue
			}
			a.wg.Add(1)
			a.enumerate(src, timeout)
		}
	}

	a.wg.Wait()
}

func (a *aggregator) enumerate(src Source, timeout time.Duration) {
	defer a.wg.Done()
	if src == nil {
		return
	}

	name := strings.TrimSpace(src.Name())
	if name == "" {
		name = "unknown"
	}

	callCtx, cancel := context.WithTimeout(a.ctx, timeout)
	defer cancel()

	subdomains, err := src.Enumerate(callCtx, a.domain)
	if err != nil {
		a.errors.Store(name, err)
		a.emit(Event{Source: name, Err: err})
		return
	}

	for _, subdomain := range subdomains {
		norm := strings.ToLower(strings.TrimSpace(subdomain))
		if norm == "" {
			continue
		}

		value := &sync.Map{}
		stored, loaded := a.seen.LoadOrStore(norm, value)
		sourcesMap := value
		if loaded {
			sourcesMap = stored.(*sync.Map)
		}

		if _, exists := sourcesMap.Load(name); exists {
			continue
		}
		sourcesMap.Store(name, struct{}{})

		a.emit(Event{Source: name, Subdomain: norm, New: !loaded})
	}
}

func (a *aggregator) emit(event Event) {
	select {
	case <-a.ctx.Done():
		return
	case a.events <- event:
	}
}

func (a *aggregator) wait() AggregateResult {
	a.waitOnce.Do(func() {
		a.wg.Wait()
	})

	result := AggregateResult{
		Subdomains: make(map[string][]string),
		Errors:     make(map[string]error),
	}

	a.seen.Range(func(key, value any) bool {
		subdomain, ok := key.(string)
		if !ok || subdomain == "" {
			return true
		}
		sourcesMap, ok := value.(*sync.Map)
		if !ok {
			return true
		}

		sources := make([]string, 0)
		sourcesMap.Range(func(sourceKey, _ any) bool {
			if source, ok := sourceKey.(string); ok && source != "" {
				sources = append(sources, source)
			}
			return true
		})
		if len(sources) > 0 {
			sort.Strings(sources)
			result.Subdomains[subdomain] = sources
		}
		return true
	})

	a.errors.Range(func(key, value any) bool {
		name, ok := key.(string)
		if !ok || name == "" {
			return true
		}
		if err, ok := value.(error); ok && err != nil {
			result.Errors[name] = err
		}
		return true
	})

	return result
}
