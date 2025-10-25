package passive

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type stubSource struct {
	name       string
	subdomains []string
	err        error
	delay      time.Duration
}

func (s *stubSource) Name() string { return s.name }

func (s *stubSource) Enumerate(ctx context.Context, domain string) ([]string, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.subdomains, s.err
}

func TestAggregate(t *testing.T) {
	ctx := context.Background()
	sources := []Source{
		&stubSource{name: "one", subdomains: []string{"A.example.com", "b.example.com"}},
		&stubSource{name: "two", subdomains: []string{"b.example.com", "c.example.com"}},
		&stubSource{name: "three", err: errors.New("boom")},
	}

	res := Aggregate(ctx, "example.com", sources)
	expected := map[string][]string{
		"a.example.com": {"one"},
		"b.example.com": {"one", "two"},
		"c.example.com": {"two"},
	}
	if !reflect.DeepEqual(res.Subdomains, expected) {
		t.Fatalf("unexpected aggregation: %#v", res.Subdomains)
	}
	if res.Errors["three"] == nil {
		t.Fatalf("expected error recorded for source three")
	}
}

func TestAggregateEmptyInput(t *testing.T) {
	res := Aggregate(context.Background(), "", nil)
	if len(res.Subdomains) != 0 || len(res.Errors) != 0 {
		t.Fatalf("expected empty result, got %+v", res)
	}
}

func TestAggregateStream(t *testing.T) {
	ctx := context.Background()
	sources := []Source{
		&stubSource{name: "one", subdomains: []string{"alpha.example.com", "beta.example.com"}},
		&stubSource{name: "two", subdomains: []string{"beta.example.com"}, delay: 10 * time.Millisecond},
		&stubSource{name: "fail", err: errors.New("boom")},
	}

	events, waitFn := AggregateStream(ctx, "example.com", sources, Options{Parallel: true, SourceTimeout: 30 * time.Second})

	var stream []Event
	for event := range events {
		stream = append(stream, event)
	}

	result := waitFn()

	if len(stream) != 4 {
		t.Fatalf("expected 4 events, got %d", len(stream))
	}

	var firstNew, duplicate Event
	var errorEvent Event
	for _, event := range stream {
		switch {
		case event.Err != nil:
			errorEvent = event
		case event.Subdomain == "beta.example.com" && event.Source == "one":
			firstNew = event
		case event.Subdomain == "beta.example.com" && event.Source == "two":
			duplicate = event
		}
	}

	if errorEvent.Err == nil || errorEvent.Source != "fail" {
		t.Fatalf("expected error event for fail source, got %+v", errorEvent)
	}
	if !firstNew.New {
		t.Fatalf("expected first discovery to be marked new")
	}
	if duplicate.New {
		t.Fatalf("expected duplicate discovery to be marked as existing")
	}

	if len(result.Subdomains["beta.example.com"]) != 2 {
		t.Fatalf("expected beta.example.com to have two sources, got %+v", result.Subdomains)
	}
}
