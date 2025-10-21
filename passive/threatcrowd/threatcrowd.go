package threatcrowd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://www.threatcrowd.org/searchApi/v2/domain/report/"
	defaultTimeout = 20 * time.Second
)

type Option func(*Client)

type Client struct {
	httpClient *http.Client
	baseURL    string
	timeout    time.Duration
}

func NewClient(opts ...Option) *Client {
	client := &Client{
		httpClient: &http.Client{Timeout: 0},
		baseURL:    defaultBaseURL,
		timeout:    defaultTimeout,
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

func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		if timeout > 0 {
			c.timeout = timeout
		}
	}
}

func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		if baseURL != "" {
			c.baseURL = strings.TrimRight(baseURL, "/") + "/"
		}
	}
}

func (c *Client) Name() string {
	return "ThreatCrowd"
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

	endpoint := fmt.Sprintf("%s?domain=%s", strings.TrimRight(c.baseURL, "/"), url.QueryEscape(domain))

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
		return nil, fmt.Errorf("threatcrowd request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("threatcrowd unexpected status: %d", resp.StatusCode)
	}

	var tcResp response
	if err := json.NewDecoder(resp.Body).Decode(&tcResp); err != nil {
		return nil, fmt.Errorf("decoding threatcrowd response: %w", err)
	}

	if strings.EqualFold(tcResp.Response, "error") {
		message := strings.TrimSpace(tcResp.Message)
		if message == "" {
			message = "unknown error"
		}
		return nil, fmt.Errorf("threatcrowd error: %s", message)
	}

	subdomains := make(map[string]struct{})
	for _, subdomain := range tcResp.Subdomains {
		name := strings.ToLower(strings.TrimSpace(subdomain))
		if name == "" {
			continue
		}
		subdomains[name] = struct{}{}
	}

	results := make([]string, 0, len(subdomains))
	for subdomain := range subdomains {
		results = append(results, subdomain)
	}
	sort.Strings(results)
	return results, nil
}

type response struct {
	Response   string   `json:"response"`
	Message    string   `json:"message"`
	Subdomains []string `json:"subdomains"`
}
