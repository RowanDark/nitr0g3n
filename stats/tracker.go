package stats

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yourusername/nitr0g3n/logging"
)

type Options struct {
	Logger   *logging.Logger
	Interval time.Duration
}

type Tracker struct {
	mu       sync.RWMutex
	start    time.Time
	total    int
	attempts int
	resolved int

	sourceBreakdown map[string]int
	activeSources   int
	passiveSources  int

	logger   *logging.Logger
	interval time.Duration
	ticker   *time.Ticker
	done     chan struct{}
	stopOnce sync.Once
}

type Snapshot struct {
	TotalFound     int
	Attempts       int
	Resolved       int
	Sources        map[string]int
	ActiveSources  int
	PassiveSources int
	Duration       time.Duration
}

func NewTracker(opts Options) *Tracker {
	interval := opts.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &Tracker{
		logger:          opts.Logger,
		interval:        interval,
		sourceBreakdown: make(map[string]int),
		done:            make(chan struct{}),
	}
}

func (t *Tracker) Start(ctxDone <-chan struct{}) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.start = time.Now()
	t.mu.Unlock()

	if t.logger == nil {
		return
	}

	t.ticker = time.NewTicker(t.interval)
	go func() {
		for {
			select {
			case <-t.ticker.C:
				t.logSnapshot(false)
			case <-ctxDone:
				return
			case <-t.done:
				return
			}
		}
	}()
}

func (t *Tracker) Stop() Snapshot {
	if t == nil {
		return Snapshot{}
	}
	t.stopOnce.Do(func() {
		close(t.done)
		if t.ticker != nil {
			t.ticker.Stop()
		}
	})
	return t.Snapshot()
}

func (t *Tracker) RecordAttempt(resolved bool) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.attempts++
	if resolved {
		t.resolved++
	}
	t.mu.Unlock()
}

func (t *Tracker) RecordDiscovery(sources []string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.total++
	for _, source := range sources {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}
		t.sourceBreakdown[source]++
		if strings.HasPrefix(strings.ToLower(source), "active:") {
			t.activeSources++
		} else {
			t.passiveSources++
		}
	}
	t.mu.Unlock()
}

func (t *Tracker) Snapshot() Snapshot {
	if t == nil {
		return Snapshot{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	copyMap := make(map[string]int, len(t.sourceBreakdown))
	for key, value := range t.sourceBreakdown {
		copyMap[key] = value
	}
	duration := time.Duration(0)
	if !t.start.IsZero() {
		duration = time.Since(t.start)
	}
	return Snapshot{
		TotalFound:     t.total,
		Attempts:       t.attempts,
		Resolved:       t.resolved,
		Sources:        copyMap,
		ActiveSources:  t.activeSources,
		PassiveSources: t.passiveSources,
		Duration:       duration,
	}
}

func (s Snapshot) ResolutionRate() float64 {
	if s.Attempts == 0 {
		return 0
	}
	return (float64(s.Resolved) / float64(s.Attempts)) * 100
}

func (s Snapshot) ActivePassiveRatio() string {
	return fmt.Sprintf("%d:%d", s.ActiveSources, s.PassiveSources)
}

func (t *Tracker) logSnapshot(final bool) {
	if t == nil || t.logger == nil {
		return
	}
	snapshot := t.Snapshot()
	if final {
		t.logger.Infof("Scan statistics: %s", t.renderSnapshot(snapshot))
		return
	}
	t.logger.Infof("Stats update: %s", t.renderSnapshot(snapshot))
}

func (t *Tracker) renderSnapshot(s Snapshot) string {
	parts := []string{
		fmt.Sprintf("total=%d", s.TotalFound),
		fmt.Sprintf("attempts=%d", s.Attempts),
		fmt.Sprintf("resolution_rate=%.1f%%", s.ResolutionRate()),
		fmt.Sprintf("active_passive=%s", s.ActivePassiveRatio()),
		fmt.Sprintf("duration=%s", s.Duration.Truncate(time.Second)),
	}
	if len(s.Sources) > 0 {
		parts = append(parts, fmt.Sprintf("sources=%s", FormatSourceBreakdown(s.Sources, 5)))
	}
	return strings.Join(parts, " | ")
}

// FormatSourceBreakdown converts a map of source counts into a human readable string.
func FormatSourceBreakdown(sources map[string]int, limit int) string {
	if limit <= 0 {
		limit = len(sources)
	}
	type item struct {
		name  string
		count int
	}
	entries := make([]item, 0, len(sources))
	for name, count := range sources {
		entries = append(entries, item{name: name, count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count == entries[j].count {
			return entries[i].name < entries[j].name
		}
		return entries[i].count > entries[j].count
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	formatted := make([]string, 0, len(entries))
	for _, entry := range entries {
		formatted = append(formatted, fmt.Sprintf("%s=%d", entry.name, entry.count))
	}
	return strings.Join(formatted, ", ")
}
