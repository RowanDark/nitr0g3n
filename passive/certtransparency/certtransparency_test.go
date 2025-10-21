package certtransparency

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type response struct {
	NameValue string `json:"name_value"`
}

func TestEnumerateFiltersAndDeduplicates(t *testing.T) {
	data := []response{
		{NameValue: "api.example.com"},
		{NameValue: "WWW.EXAMPLE.COM"},
		{NameValue: "*.example.com"},
		{NameValue: "mail.example.com\nftp.example.com"},
		{NameValue: "notexample.org"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write(mustJSON(data)); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))

	got, err := client.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Enumerate() error = %v", err)
	}

	want := []string{"api.example.com", "ftp.example.com", "mail.example.com", "www.example.com"}
	if len(got) != len(want) {
		t.Fatalf("expected %d results, got %d (%v)", len(want), len(got), got)
	}

	for i, sub := range got {
		if sub != want[i] {
			t.Fatalf("expected %s at index %d, got %s", want[i], i, sub)
		}
	}
}

func TestEnumerateRetriesOnServerError(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		if _, err := w.Write(mustJSON([]response{{NameValue: "api.example.com"}})); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(
		WithBaseURL(server.URL),
		WithInitialBackoff(10*time.Millisecond),
		WithTimeout(2*time.Second),
	)

	got, err := client.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Enumerate() error = %v", err)
	}

	if len(got) != 1 || got[0] != "api.example.com" {
		t.Fatalf("unexpected results: %v", got)
	}
}

func TestEnumerateHonoursContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		http.Error(w, "slow", http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewClient(
		WithBaseURL(server.URL),
		WithInitialBackoff(500*time.Millisecond),
		WithTimeout(5*time.Second),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if _, err := client.Enumerate(ctx, "example.com"); err == nil {
		t.Fatalf("expected context error, got nil")
	}
}

func mustJSON(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
