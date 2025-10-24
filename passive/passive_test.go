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
