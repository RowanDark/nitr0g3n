package certtransparency

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEnumerateSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.RawQuery; !strings.Contains(got, "q=%25.example.com") {
			t.Fatalf("unexpected query: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
                        {"name_value":"www.example.com\n*.example.com"},
                        {"name_value":"api.example.com"},
                        {"name_value":"WWW.EXAMPLE.COM"}
                ]`))
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithBaseURL(server.URL),
		WithTimeout(2*time.Second),
		WithMaxRetries(0),
	)

	subdomains, err := client.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []string{"api.example.com", "www.example.com"}
	if len(subdomains) != len(expected) {
		t.Fatalf("expected %d results, got %d", len(expected), len(subdomains))
	}
	for i, sub := range expected {
		if subdomains[i] != sub {
			t.Fatalf("unexpected result at %d: %s", i, subdomains[i])
		}
	}
}

func TestEnumerateError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithBaseURL(server.URL),
		WithTimeout(2*time.Second),
		WithInitialBackoff(10*time.Millisecond),
		WithMaxRetries(0),
	)

	if _, err := client.Enumerate(context.Background(), "example.com"); err == nil {
		t.Fatalf("expected error from enumerate")
	}
}

func TestRetryAfterDuration(t *testing.T) {
	if got := retryAfterDuration("60"); got != 60*time.Second {
		t.Fatalf("expected 60s duration, got %s", got)
	}
	future := time.Now().Add(5 * time.Second).UTC().Format(http.TimeFormat)
	if got := retryAfterDuration(future); got <= 0 {
		t.Fatalf("expected positive duration for retry-after header")
	}
	if got := retryAfterDuration("invalid"); got != 0 {
		t.Fatalf("expected zero duration for invalid header")
	}
}
