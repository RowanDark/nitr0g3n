package virustotal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEnumerateSuccess(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "test-key" {
			t.Fatalf("missing api key header")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/page2"):
			json.NewEncoder(w).Encode(response{
				Data: []domainData{{ID: "api.example.com"}},
			})
		case strings.Contains(r.URL.Path, "/subdomains"):
			json.NewEncoder(w).Encode(response{
				Data:  []domainData{{ID: "www.example.com"}},
				Links: links{Next: server.URL + "/page2"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient("test-key",
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

func TestEnumerateRequiresAPIKey(t *testing.T) {
	client := NewClient("")
	if _, err := client.Enumerate(context.Background(), "example.com"); err == nil {
		t.Fatalf("expected error without api key")
	}
}
