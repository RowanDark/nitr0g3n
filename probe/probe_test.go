package probe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

type stubTransport struct {
	statuses map[string]int
	failures map[string]error
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.URL.String()
	if err := s.failures[key]; err != nil {
		return nil, err
	}
	status := s.statuses[key]
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(nil))}, nil
}

func TestNewClientDefaults(t *testing.T) {
	client := NewClient(Options{})
	if client.http.Timeout != 10*time.Second {
		t.Fatalf("expected default timeout of 10s, got %s", client.http.Timeout)
	}
}

func TestProbe(t *testing.T) {
	transport := &stubTransport{
		statuses: map[string]int{
			"http://example.com":  http.StatusOK,
			"https://example.com": http.StatusAccepted,
		},
		failures: map[string]error{
			"https://example.com": errors.New("tls error"),
		},
	}
	httpClient := &http.Client{Transport: transport, Timeout: time.Second}
	client := NewClient(Options{HTTPClient: httpClient})

	services := client.Probe(context.Background(), "example.com")
	if len(services) != 2 {
		t.Fatalf("expected two probe results, got %d", len(services))
	}
	if services[0].StatusCode != http.StatusOK || services[1].Error == "" {
		t.Fatalf("unexpected probe results: %+v", services)
	}
}
