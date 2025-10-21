package virustotal

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
	defaultBaseURL = "https://www.virustotal.com"
	defaultTimeout = 30 * time.Second
)

type Option func(*Client)

type Client struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
	timeout    time.Duration
}

func NewClient(apiKey string, opts ...Option) *Client {
	client := &Client{
		apiKey:     strings.TrimSpace(apiKey),
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

func (c *Client) Name() string {
	return "VirusTotal"
}

func (c *Client) Enumerate(ctx context.Context, domain string) ([]string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, errors.New("domain cannot be empty")
	}

	if strings.TrimSpace(c.apiKey) == "" {
		return nil, errors.New("virustotal api key is required")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	endpoint := fmt.Sprintf("%s/api/v3/domains/%s/subdomains?limit=40", c.baseURL, url.PathEscape(domain))

	subdomains := make(map[string]struct{})
	for endpoint != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set("x-apikey", c.apiKey)
		req.Header.Set("User-Agent", "nitr0g3n/1.0")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("virustotal request failed: %w", err)
		}

		var vtResp response
		if err := json.NewDecoder(resp.Body).Decode(&vtResp); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decoding virustotal response: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			if vtResp.Error != nil && vtResp.Error.Message != "" {
				return nil, fmt.Errorf("virustotal error: %s", vtResp.Error.Message)
			}
			return nil, fmt.Errorf("virustotal unexpected status: %d", resp.StatusCode)
		}

		for _, entry := range vtResp.Data {
			name := strings.ToLower(strings.TrimSpace(entry.ID))
			if name == "" {
				continue
			}
			subdomains[name] = struct{}{}
		}

		endpoint = strings.TrimSpace(vtResp.Links.Next)
	}

	results := make([]string, 0, len(subdomains))
	for subdomain := range subdomains {
		results = append(results, subdomain)
	}
	sort.Strings(results)
	return results, nil
}

type response struct {
	Data  []domainData `json:"data"`
	Links links        `json:"links"`
	Error *apiError    `json:"error"`
}

type domainData struct {
	ID string `json:"id"`
}

type links struct {
	Next string `json:"next"`
}

type apiError struct {
	Message string `json:"message"`
}
