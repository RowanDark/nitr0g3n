package nitro

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/RowanDark/nitr0g3n/config"
	"github.com/RowanDark/nitr0g3n/logging"
	"github.com/RowanDark/nitr0g3n/passive"
	"github.com/RowanDark/nitr0g3n/resolver"
	"github.com/RowanDark/nitr0g3n/stats"
)

type stubSource struct{ name string }

func (s stubSource) Name() string                                        { return s.name }
func (s stubSource) Enumerate(context.Context, string) ([]string, error) { return nil, nil }

func TestAddSource(t *testing.T) {
	m := make(map[string][]string)
	addSource(m, "www.example.com", "passive")
	addSource(m, "www.example.com", "passive")
	addSource(m, "", "ignored")
	if len(m["www.example.com"]) != 1 {
		t.Fatalf("expected deduplicated sources, got %v", m)
	}
}

func TestMergeZoneRecords(t *testing.T) {
	target := map[string]map[string][]string{"a": {"A": {"1.1.1.1"}}}
	incoming := map[string]map[string][]string{"a": {"A": {"2.2.2.2"}}, "b": {"CNAME": {"c"}}}
	mergeZoneRecords(target, incoming)
	if len(target["a"]["A"]) != 2 || target["b"]["CNAME"][0] != "c" {
		t.Fatalf("unexpected merge result: %+v", target)
	}
}

func TestMergeResolution(t *testing.T) {
	res := resolver.Result{IPAddresses: []string{"1.1.1.1"}, DNSRecords: map[string][]string{"A": {"1.1.1.1"}}}
	zone := map[string][]string{"A": {"2.2.2.2"}}
	ips, records := mergeResolution(res, zone)
	if len(ips) != 2 || len(records["A"]) != 2 {
		t.Fatalf("unexpected merge: %v %v", ips, records)
	}
}

func TestDedupeSortedStrings(t *testing.T) {
	values := dedupeSortedStrings([]string{"b", "a", "a", ""})
	if len(values) != 2 || values[0] != "a" {
		t.Fatalf("unexpected dedupe result: %v", values)
	}
}

func TestMatchesScope(t *testing.T) {
	if !matchesScope("api.example.com", []string{"*.example.com"}) {
		t.Fatalf("expected wildcard match")
	}
	if matchesScope("api.example.com", []string{"*.other.com"}) {
		t.Fatalf("did not expect match")
	}
}

func TestFilterUniqueIPs(t *testing.T) {
	seen := make(map[string]struct{})
	ips, records := filterUniqueIPs([]string{"1.1.1.1", "1.1.1.1", ""}, map[string][]string{"A": {"1.1.1.1", "2.2.2.2"}}, seen)
	if len(ips) != 1 || ips[0] != "1.1.1.1" {
		t.Fatalf("unexpected ips: %v", ips)
	}
	if len(records["A"]) != 1 {
		t.Fatalf("unexpected records: %v", records)
	}
	// duplicates filtered entirely
	ips, records = filterUniqueIPs([]string{"1.1.1.1"}, records, seen)
	if len(ips) != 0 || len(records["A"]) != 1 {
		t.Fatalf("expected duplicates to be ignored")
	}
}

func TestSelectSources(t *testing.T) {
	available := map[string]passive.Source{"one": stubSource{name: "One"}, "two": stubSource{name: "Two"}}
	sources, err := selectSources([]string{"One", "two", "one"}, available)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("expected two sources, got %d", len(sources))
	}
	if _, err := selectSources([]string{"unknown"}, available); err == nil {
		t.Fatalf("expected error for unknown source")
	}
}

func TestBuildPassiveSourcesDefault(t *testing.T) {
	cfg := &config.Config{Timeout: time.Second}
	sources, err := buildPassiveSources(cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 4 {
		t.Fatalf("expected default sources, got %d", len(sources))
	}
}

func TestLogScanSummary(t *testing.T) {
	cfg := &config.Config{Domain: "example.com", Format: config.FormatJSON}
	var console bytes.Buffer
	logger, err := logging.New(logging.Options{Level: logging.LevelInfo, Console: &console})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	snapshot := stats.Snapshot{TotalFound: 2, Attempts: 2, Resolved: 1, Sources: map[string]int{"a": 1}}
	logScanSummary(logger, cfg, snapshot)
	if !bytes.Contains(console.Bytes(), []byte("Scan complete")) {
		t.Fatalf("expected summary output, got %s", console.String())
	}
}
