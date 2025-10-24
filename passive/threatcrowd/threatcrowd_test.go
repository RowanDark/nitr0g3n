package threatcrowd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEnumerateSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(response{
			Response:   "ok",
			Subdomains: []string{"www.example.com", "api.example.com", "www.example.com"},
		})
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithBaseURL(server.URL),
		WithTimeout(time.Second),
	)

	subdomains, err := client.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subdomains) != 2 {
		t.Fatalf("expected 2 results, got %d", len(subdomains))
	}
}

func TestEnumerateAPIFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(response{Response: "error", Message: "limit"})
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithBaseURL(server.URL),
		WithTimeout(time.Second),
	)

	if _, err := client.Enumerate(context.Background(), "example.com"); err == nil {
		t.Fatalf("expected error from API failure")
	}
}
