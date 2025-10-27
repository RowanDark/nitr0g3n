package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/RowanDark/nitr0g3n/output"
)

// Options configures the webhook notifier.
type Options struct {
	Endpoint string
	Secret   string
	Domain   string
	Client   *http.Client
	Logger   io.Writer
}

// Notifier delivers discovery events to a configured webhook endpoint.
type Notifier struct {
	endpoint string
	secret   string
	domain   string
	client   *http.Client
	logger   io.Writer
}

type payload struct {
	Event   string        `json:"event"`
	Domain  string        `json:"domain"`
	Record  output.Record `json:"record"`
	SentAt  time.Time     `json:"sent_at"`
	Version string        `json:"version"`
}

// New initialises a webhook notifier. It returns nil when the endpoint is empty.
func New(opts Options) (*Notifier, error) {
	endpoint := strings.TrimSpace(opts.Endpoint)
	if endpoint == "" {
		return nil, nil
	}
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("webhook endpoint must be an absolute URL")
	}

	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	notifier := &Notifier{
		endpoint: endpoint,
		secret:   strings.TrimSpace(opts.Secret),
		domain:   strings.TrimSpace(opts.Domain),
		client:   client,
		logger:   opts.Logger,
	}
	return notifier, nil
}

// Notify posts the provided record to the webhook endpoint.
func (n *Notifier) Notify(ctx context.Context, domain string, record output.Record) error {
	if n == nil {
		return nil
	}

	if domain == "" {
		domain = n.domain
	}

	body := payload{
		Event:   "subdomain.discovered",
		Domain:  domain,
		Record:  record,
		SentAt:  time.Now().UTC(),
		Version: "1",
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "nitr0g3n-webhook/1.0")
	req.Header.Set("X-Nitr0g3n-Event", body.Event)

	if n.secret != "" {
		mac := hmac.New(sha256.New, []byte(n.secret))
		mac.Write(data)
		signature := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Nitr0g3n-Signature", signature)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("deliver webhook: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook responded with status %s", resp.Status)
	}

	n.logf("Webhook delivered for %s (%s)\n", record.Subdomain, domain)
	return nil
}

func (n *Notifier) logf(format string, args ...interface{}) {
	if n == nil || n.logger == nil {
		return
	}
	fmt.Fprintf(n.logger, format, args...)
}
