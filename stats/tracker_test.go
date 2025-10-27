package stats

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/RowanDark/nitr0g3n/logging"
)

func TestTrackerSnapshot(t *testing.T) {
	tracker := NewTracker(Options{})
	tracker.RecordAttempt(true)
	tracker.RecordAttempt(false)
	tracker.RecordDiscovery([]string{"passive:crtsh", "active:brute"})
	snapshot := tracker.Snapshot()
	if snapshot.TotalFound != 1 || snapshot.Resolved != 1 || snapshot.Attempts != 2 {
		t.Fatalf("unexpected snapshot values: %+v", snapshot)
	}
	if snapshot.ResolutionRate() <= 0 {
		t.Fatalf("expected positive resolution rate")
	}
	if snapshot.ActivePassiveRatio() != "1:1" {
		t.Fatalf("unexpected ratio: %s", snapshot.ActivePassiveRatio())
	}
}

func TestTrackerLogging(t *testing.T) {
	var buf bytes.Buffer
	logger, err := logging.New(logging.Options{Level: logging.LevelInfo, Console: &buf})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	tracker := NewTracker(Options{Logger: logger, Interval: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	tracker.Start(ctx.Done())
	tracker.RecordDiscovery([]string{"passive:crtsh"})
	tracker.RecordAttempt(true)
	time.Sleep(2 * time.Millisecond)
	cancel()
	snapshot := tracker.Stop()
	tracker.logSnapshot(true)

	if snapshot.TotalFound == 0 {
		t.Fatalf("expected snapshot to reflect discoveries")
	}
	if !strings.Contains(buf.String(), "Stats update") && !strings.Contains(buf.String(), "Scan statistics") {
		t.Fatalf("expected log output, got %s", buf.String())
	}
}

func TestFormatSourceBreakdown(t *testing.T) {
	breakdown := map[string]int{"b": 2, "a": 5, "c": 1}
	formatted := FormatSourceBreakdown(breakdown, 2)
	if !strings.Contains(formatted, "a=5") || !strings.Contains(formatted, "b=2") {
		t.Fatalf("unexpected breakdown: %s", formatted)
	}
}
