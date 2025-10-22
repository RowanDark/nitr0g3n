package probe

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/yourusername/nitr0g3n/output"
)

type Options struct {
	Timeout time.Duration
}

func NewClient(opts Options) *Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		http: &http.Client{Timeout: timeout},
	}
}

type Client struct {
	http *http.Client
}

func (c *Client) Probe(ctx context.Context, hostname string) []output.HTTPService {
	if hostname == "" {
		return nil
	}

	schemes := []string{"http", "https"}
	results := make([]output.HTTPService, 0, len(schemes))

	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s", scheme, hostname)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results = append(results, output.HTTPService{URL: url, Error: err.Error()})
			continue
		}

		resp, err := c.http.Do(req)
		if err != nil {
			results = append(results, output.HTTPService{URL: url, Error: err.Error()})
			continue
		}

		_ = resp.Body.Close()
		results = append(results, output.HTTPService{URL: url, StatusCode: resp.StatusCode})
	}

	return results
}
