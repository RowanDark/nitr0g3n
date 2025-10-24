package hackertarget

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEnumerateSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("www.example.com,93.184.216.34\napi.example.com,93.184.216.34\n"))
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
	if subdomains[0] != "api.example.com" || subdomains[1] != "www.example.com" {
		t.Fatalf("unexpected subdomains: %v", subdomains)
	}
}

func TestEnumerateStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	client := NewClient(
		WithHTTPClient(server.Client()),
		WithBaseURL(server.URL),
		WithTimeout(time.Second),
	)

	if _, err := client.Enumerate(context.Background(), "example.com"); err == nil {
		t.Fatalf("expected error on non-200 response")
	}
}
