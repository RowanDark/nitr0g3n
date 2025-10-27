package oxg3n

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RowanDark/nitr0g3n/output"
)

func TestNewExporterValidation(t *testing.T) {
	if exp, err := NewExporter(Options{}); err != nil || exp != nil {
		t.Fatalf("expected nil exporter when endpoint missing")
	}
	if _, err := NewExporter(Options{Endpoint: "example"}); err == nil {
		t.Fatalf("expected error for non-absolute endpoint")
	}
}

func TestExporterAddRecordAndFlush(t *testing.T) {
	var requests []payload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var body payload
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}
		requests = append(requests, body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var logs bytes.Buffer
	client := server.Client()
	exporter, err := NewExporter(Options{
		Endpoint:  server.URL,
		Domain:    "example.com",
		BatchSize: 1,
		Client:    client,
		Logger:    &logs,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	record := output.Record{
		Subdomain:   "www.example.com",
		Source:      "passive:crtsh",
		IPAddresses: []string{"192.0.2.1"},
		DNSRecords:  map[string][]string{"A": []string{"192.0.2.1"}},
	}
	if err := exporter.AddRecord(context.Background(), record); err != nil {
		t.Fatalf("add record failed: %v", err)
	}

	summary, err := exporter.Flush(context.Background())
	if err != nil {
		t.Fatalf("flush failed: %v", err)
	}
	if summary.TotalRecords != 1 || summary.UniqueSubdomains != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}

	if len(requests) != 2 {
		t.Fatalf("expected two HTTP requests, got %d", len(requests))
	}
	if requests[0].Final || !requests[1].Final {
		t.Fatalf("expected first batch non-final and second batch final")
	}
	if !bytes.Contains(logs.Bytes(), []byte("Exported 1 record")) {
		t.Fatalf("expected log output, got %s", logs.String())
	}
}

func TestExporterRetriesFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	exporter, err := NewExporter(Options{Endpoint: server.URL, BatchSize: 1, Client: server.Client()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = exporter.AddRecord(ctx, output.Record{Subdomain: "a"})
	if err == nil {
		t.Fatalf("expected error when server returns non-200")
	}
}
