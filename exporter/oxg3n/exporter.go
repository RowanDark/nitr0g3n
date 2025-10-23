package oxg3n

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yourusername/nitr0g3n/output"
)

// Options configure the 0xg3n exporter.
type Options struct {
	Endpoint  string
	APIKey    string
	Domain    string
	BatchSize int
	Client    *http.Client
	Logger    io.Writer
}

// Exporter batches discovery records and ships them to the 0xg3n hub API.
type Exporter struct {
	endpoint  string
	apiKey    string
	domain    string
	client    *http.Client
	batch     []record
	batchSize int
	logger    io.Writer

	totalRecords     int
	resolvedRecords  int
	uniqueSubdomains map[string]struct{}
	uniqueIPs        map[string]struct{}
	batchesSent      int
	finalSent        bool
}

type payload struct {
	Domain  string    `json:"domain"`
	BatchID int       `json:"batch_id"`
	Records []record  `json:"records"`
	Summary summary   `json:"summary"`
	Final   bool      `json:"final"`
	SentAt  time.Time `json:"sent_at"`
}

type summary struct {
	TotalRecords     int `json:"total_records"`
	ResolvedRecords  int `json:"resolved_records"`
	UniqueSubdomains int `json:"unique_subdomains"`
	UniqueIPs        int `json:"unique_ips"`
	BatchesSent      int `json:"batches_sent"`
}

type record struct {
	Subdomain    string               `json:"subdomain"`
	Source       string               `json:"source"`
	Timestamp    string               `json:"timestamp"`
	IPAddresses  []string             `json:"ip_addresses,omitempty"`
	DNSRecords   map[string][]string  `json:"dns_records,omitempty"`
	HTTPServices []output.HTTPService `json:"http_services,omitempty"`
}

// NewExporter constructs a configured exporter. It returns nil when the endpoint is empty.
func NewExporter(opts Options) (*Exporter, error) {
	endpoint := strings.TrimSpace(opts.Endpoint)
	if endpoint == "" {
		return nil, nil
	}
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("0xg3n endpoint must be an absolute URL")
	}

	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	batchSize := opts.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}

	exp := &Exporter{
		endpoint:         endpoint,
		apiKey:           strings.TrimSpace(opts.APIKey),
		domain:           strings.TrimSpace(opts.Domain),
		client:           client,
		batchSize:        batchSize,
		logger:           opts.Logger,
		uniqueSubdomains: make(map[string]struct{}),
		uniqueIPs:        make(map[string]struct{}),
	}
	return exp, nil
}

// AddRecord schedules a record for export, sending a batch if the threshold is met.
func (e *Exporter) AddRecord(ctx context.Context, rec output.Record) error {
	if e == nil {
		return nil
	}

	converted := record{
		Subdomain:    rec.Subdomain,
		Source:       rec.Source,
		Timestamp:    rec.Timestamp,
		IPAddresses:  append([]string(nil), rec.IPAddresses...),
		HTTPServices: append([]output.HTTPService(nil), rec.HTTPServices...),
	}

	if converted.Timestamp == "" {
		converted.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	if rec.DNSRecords != nil {
		converted.DNSRecords = make(map[string][]string, len(rec.DNSRecords))
		for recordType, values := range rec.DNSRecords {
			converted.DNSRecords[recordType] = append([]string(nil), values...)
		}
	}

	e.batch = append(e.batch, converted)
	e.totalRecords++
	e.uniqueSubdomains[strings.ToLower(rec.Subdomain)] = struct{}{}
	if len(rec.IPAddresses) > 0 || len(rec.DNSRecords) > 0 {
		e.resolvedRecords++
	}
	for _, ip := range rec.IPAddresses {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			e.uniqueIPs[ip] = struct{}{}
		}
	}

	if len(e.batch) >= e.batchSize {
		return e.sendCurrentBatch(ctx, false)
	}

	return nil
}

// Flush sends any remaining records and returns the export summary.
func (e *Exporter) Flush(ctx context.Context) (summary, error) {
	if e == nil {
		return summary{}, nil
	}
	if len(e.batch) > 0 {
		if err := e.sendCurrentBatch(ctx, true); err != nil {
			return summary{}, err
		}
	} else if !e.finalSent {
		if err := e.postPayload(ctx, payload{
			Domain:  e.domain,
			BatchID: e.batchesSent,
			Records: nil,
			Summary: e.buildSummary(),
			Final:   true,
			SentAt:  time.Now().UTC(),
		}); err != nil {
			return summary{}, err
		}
		e.finalSent = true
	}

	return e.buildSummary(), nil
}

func (e *Exporter) sendCurrentBatch(ctx context.Context, final bool) error {
	if len(e.batch) == 0 {
		return nil
	}
	e.batchesSent++
	payload := payload{
		Domain:  e.domain,
		BatchID: e.batchesSent,
		Records: e.batch,
		Summary: e.buildSummary(),
		Final:   final,
		SentAt:  time.Now().UTC(),
	}
	if err := e.postPayload(ctx, payload); err != nil {
		e.batchesSent--
		return err
	}
	e.batch = nil
	if final {
		e.finalSent = true
	}
	return nil
}

func (e *Exporter) postPayload(ctx context.Context, body payload) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("serialising payload: %w", err)
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(data))
		if reqErr != nil {
			return fmt.Errorf("creating export request: %w", reqErr)
		}
		req.Header.Set("Content-Type", "application/json")
		if e.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+e.apiKey)
		}

		resp, err := e.client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				lastErr = nil
				break
			}
			lastErr = fmt.Errorf("0xg3n API responded with status %s", resp.Status)
		}

		if lastErr == nil {
			break
		}

		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	if lastErr != nil {
		e.logf("0xg3n export failed after retries: %v\n", lastErr)
		return lastErr
	}

	e.logf("Exported %d record(s) to 0xg3n (batch %d, final=%t)\n", len(body.Records), body.BatchID, body.Final)
	return nil
}

func (e *Exporter) buildSummary() summary {
	return summary{
		TotalRecords:     e.totalRecords,
		ResolvedRecords:  e.resolvedRecords,
		UniqueSubdomains: len(e.uniqueSubdomains),
		UniqueIPs:        len(e.uniqueIPs),
		BatchesSent:      e.batchesSent,
	}
}

func (e *Exporter) logf(format string, args ...interface{}) {
	if e.logger == nil {
		return
	}
	fmt.Fprintf(e.logger, format, args...)
}
