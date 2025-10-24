package probe

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yourusername/nitr0g3n/output"
)

type Options struct {
	Timeout       time.Duration
	HTTPClient    *http.Client
	MaxBodySize   int64
	ScreenshotDir string
}

func NewClient(opts Options) *Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	client.Timeout = timeout

	maxBody := opts.MaxBodySize
	if maxBody <= 0 {
		maxBody = 512 * 1024
	}

	screenshotDir := strings.TrimSpace(opts.ScreenshotDir)
	if screenshotDir != "" {
		_ = os.MkdirAll(screenshotDir, 0o755)
	}

	return &Client{http: client, maxBodySize: maxBody, screenshotDir: screenshotDir}
}

type Client struct {
	http          *http.Client
	maxBodySize   int64
	screenshotDir string
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

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, c.maxBodySize))
		_ = resp.Body.Close()

		service := output.HTTPService{URL: url, StatusCode: resp.StatusCode}
		service.Banner = strings.TrimSpace(resp.Header.Get("Server"))

		if readErr != nil {
			if service.Error == "" {
				service.Error = readErr.Error()
			} else {
				service.Error = fmt.Sprintf("%s; body: %s", service.Error, readErr.Error())
			}
		}

		if len(body) > 0 {
			service.Title = extractTitle(body)
			service.Snippet = extractSnippet(body, 160)
		}

		if c.screenshotDir != "" {
			path, shotErr := c.captureScreenshot(hostname, scheme, service)
			if shotErr != nil {
				if service.Error == "" {
					service.Error = fmt.Sprintf("screenshot: %s", shotErr.Error())
				} else {
					service.Error = fmt.Sprintf("%s; screenshot: %s", service.Error, shotErr.Error())
				}
			} else if path != "" {
				service.ScreenshotPath = path
			}
		}

		results = append(results, service)
	}

	return results
}

func extractTitle(body []byte) string {
	lower := strings.ToLower(string(body))
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += len("<title>")
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	title := string(body[start : start+end])
	title = html.UnescapeString(strings.TrimSpace(title))
	if !utf8.ValidString(title) {
		return ""
	}
	return normalizeWhitespace(title)
}

func extractSnippet(body []byte, limit int) string {
	if limit <= 0 || len(body) == 0 {
		return ""
	}
	snippet := string(body)
	snippet = html.UnescapeString(snippet)
	snippet = normalizeWhitespace(snippet)
	if len(snippet) == 0 {
		return ""
	}

	runes := []rune(snippet)
	if len(runes) > limit {
		runes = runes[:limit]
	}
	return strings.TrimSpace(string(runes))
}

func normalizeWhitespace(input string) string {
	if input == "" {
		return ""
	}
	fields := strings.Fields(input)
	return strings.Join(fields, " ")
}

func (c *Client) captureScreenshot(hostname, scheme string, service output.HTTPService) (string, error) {
	if c.screenshotDir == "" {
		return "", nil
	}

	lines := []string{fmt.Sprintf("%s://%s", scheme, hostname)}
	if service.Title != "" {
		lines = append(lines, fmt.Sprintf("Title: %s", service.Title))
	}
	if service.Banner != "" {
		lines = append(lines, fmt.Sprintf("Banner: %s", service.Banner))
	}
	if service.StatusCode > 0 {
		lines = append(lines, fmt.Sprintf("Status: %d", service.StatusCode))
	}
	if service.Snippet != "" {
		lines = append(lines, fmt.Sprintf("Snippet: %s", service.Snippet))
	}

	data, err := renderScreenshot(lines)
	if err != nil {
		return "", err
	}

	filename := fmt.Sprintf("%s_%s.png", sanitizeFilename(hostname), scheme)
	path := filepath.Join(c.screenshotDir, filename)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}
