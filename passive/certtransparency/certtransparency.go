package certtransparency

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	defaultBaseURL        = "https://crt.sh"
	defaultTimeout        = 30 * time.Second
	defaultMaxRetries     = 3
	defaultInitialBackoff = 1 * time.Second
)

type Option func(*Client)

type Client struct {
	httpClient *http.Client
	baseURL    string
	timeout    time.Duration
	maxRetries int
	backoff    time.Duration
}

type record struct {
	NameValue string `json:"name_value"`
}

func NewClient(opts ...Option) *Client {
	client := &Client{
		httpClient: &http.Client{Timeout: 0},
		baseURL:    defaultBaseURL,
		timeout:    defaultTimeout,
		maxRetries: defaultMaxRetries,
		backoff:    defaultInitialBackoff,
	}

	for _, opt := range opts {
		opt(client)
	}

	return client
}

func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		if baseURL != "" {
			c.baseURL = strings.TrimRight(baseURL, "/")
		}
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		if timeout > 0 {
			c.timeout = timeout
		}
	}
}

func WithMaxRetries(maxRetries int) Option {
	return func(c *Client) {
		if maxRetries >= 0 {
			c.maxRetries = maxRetries
		}
	}
}

func WithInitialBackoff(backoff time.Duration) Option {
	return func(c *Client) {
		if backoff > 0 {
			c.backoff = backoff
		}
	}
}

func (c *Client) Enumerate(ctx context.Context, domain string) ([]string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, errors.New("domain cannot be empty")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	endpoint := fmt.Sprintf("%s/?q=%%25.%s&output=json", c.baseURL, url.QueryEscape(domain))

	var lastErr error
	backoff := c.backoff
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set("User-Agent", "nitr0g3n/1.0")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
		} else {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()

			if readErr != nil {
				return nil, fmt.Errorf("reading response: %w", readErr)
			}

			switch resp.StatusCode {
			case http.StatusOK:
				return parseResponse(body, domain)
			case http.StatusTooManyRequests:
				lastErr = fmt.Errorf("received 429 Too Many Requests from crt.sh")
				if retryDelay := retryAfterDuration(resp.Header.Get("Retry-After")); retryDelay > 0 {
					backoff = retryDelay
				}
			case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
				lastErr = fmt.Errorf("received %d response from crt.sh", resp.StatusCode)
			default:
				return nil, fmt.Errorf("unexpected status code %d from crt.sh", resp.StatusCode)
			}
		}

		if attempt == c.maxRetries {
			break
		}

		select {
		case <-time.After(backoff):
			backoff *= 2
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if lastErr == nil {
		lastErr = errors.New("failed to fetch certificate transparency data")
	}
	return nil, lastErr
}

func retryAfterDuration(header string) time.Duration {
	if header == "" {
		return 0
	}

	if seconds, err := time.ParseDuration(header + "s"); err == nil {
		return seconds
	}

	if t, err := http.ParseTime(header); err == nil {
		return time.Until(t)
	}

	return 0
}

func parseResponse(body []byte, domain string) ([]string, error) {
	var records []record
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	suffix := "." + strings.TrimPrefix(domain, ".")

	subdomains := make(map[string]struct{})
	for _, rec := range records {
		names := strings.Split(rec.NameValue, "\n")
		for _, name := range names {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			if strings.Contains(name, "*") {
				continue
			}
			if !strings.HasSuffix(name, suffix) && name != domain {
				continue
			}
			subdomains[name] = struct{}{}
		}
	}

	result := make([]string, 0, len(subdomains))
	for subdomain := range subdomains {
		result = append(result, subdomain)
	}
	sort.Strings(result)
	return result, nil
}
