package output

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yourusername/nitr0g3n/config"
)

// Record captures the structured discovery data shared with downstream tooling.
type Record struct {
	Subdomain    string              `json:"subdomain"`
	IPAddresses  []string            `json:"ip_addresses"`
	Source       string              `json:"source"`
	Timestamp    string              `json:"timestamp"`
	DNSRecords   map[string][]string `json:"dns_records"`
	HTTPServices []HTTPService       `json:"http,omitempty"`
	Change       string              `json:"change,omitempty"`
}

// HTTPService captures the result of probing a single scheme/URL.
type HTTPService struct {
	URL            string `json:"url"`
	StatusCode     int    `json:"status_code"`
	Error          string `json:"error,omitempty"`
	Banner         string `json:"banner,omitempty"`
	Title          string `json:"title,omitempty"`
	ScreenshotPath string `json:"screenshot,omitempty"`
	Snippet        string `json:"snippet,omitempty"`
}

// Writer serialises discovery records to stdout or a file in a configured format.
type Writer struct {
	format        config.Format
	destination   io.Writer
	closer        io.Closer
	csvWriter     *csv.Writer
	csvHeaderSent bool
	encoder       *json.Encoder
	buffered      *bufio.Writer
}

// NewWriter creates a writer configured according to the provided options.
func NewWriter(cfg *config.Config) (*Writer, error) {
	var (
		dest   io.Writer
		closer io.Closer
		err    error
	)

	if cfg.LiveOutput() {
		dest = os.Stdout
	} else {
		if err = os.MkdirAll(filepath.Dir(cfg.OutputPath), 0o755); err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("creating output directory: %w", err)
		}

		file, ferr := os.Create(cfg.OutputPath)
		if ferr != nil {
			return nil, fmt.Errorf("opening output file: %w", ferr)
		}
		dest = file
		closer = file
	}

	writer := &Writer{format: cfg.Format}

	switch cfg.Format {
	case config.FormatJSON:
		writer.encoder = json.NewEncoder(dest)
		writer.encoder.SetEscapeHTML(false)
		if cfg.JSONPretty {
			writer.encoder.SetIndent("", "  ")
		}
	case config.FormatCSV:
		writer.csvWriter = csv.NewWriter(dest)
	case config.FormatTXT:
		if buf, ok := dest.(*bufio.Writer); ok {
			writer.buffered = buf
		} else {
			writer.buffered = bufio.NewWriter(dest)
		}
		dest = writer.buffered
	}

	writer.destination = dest
	writer.closer = closer

	return writer, nil
}

// WriteRecord persists a single discovery record using the configured format.
func (w *Writer) WriteRecord(record Record) error {
	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	if record.DNSRecords == nil {
		record.DNSRecords = map[string][]string{}
	}

	switch w.format {
	case config.FormatJSON:
		return w.encoder.Encode(record)
	case config.FormatCSV:
		return w.writeCSVRecord(record)
	case config.FormatTXT:
		return w.writeTXTRecord(record)
	default:
		return fmt.Errorf("unsupported output format: %s", w.format)
	}
}

func (w *Writer) writeCSVRecord(record Record) error {
	if w.csvWriter == nil {
		return fmt.Errorf("csv writer not initialised")
	}

	if !w.csvHeaderSent {
		header := []string{"subdomain", "ip_addresses", "source", "timestamp", "dns_records", "http_services", "change"}
		if err := w.csvWriter.Write(header); err != nil {
			return err
		}
		w.csvHeaderSent = true
	}

	dns := flattenDNSRecords(record.DNSRecords)
	row := []string{
		record.Subdomain,
		strings.Join(record.IPAddresses, ";"),
		record.Source,
		record.Timestamp,
		dns,
		flattenHTTPServices(record.HTTPServices),
		record.Change,
	}

	if err := w.csvWriter.Write(row); err != nil {
		return err
	}
	w.csvWriter.Flush()
	return w.csvWriter.Error()
}

func (w *Writer) writeTXTRecord(record Record) error {
	if w.destination == nil {
		return fmt.Errorf("txt writer not initialised")
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Subdomain: %s\n", record.Subdomain))
	builder.WriteString(fmt.Sprintf("Source: %s\n", record.Source))
	builder.WriteString(fmt.Sprintf("Timestamp: %s\n", record.Timestamp))
	if record.Change != "" {
		builder.WriteString(fmt.Sprintf("Change: %s\n", record.Change))
	}

	if len(record.IPAddresses) > 0 {
		builder.WriteString(fmt.Sprintf("IP Addresses: %s\n", strings.Join(record.IPAddresses, ", ")))
	}

	if len(record.DNSRecords) > 0 {
		keys := make([]string, 0, len(record.DNSRecords))
		for key := range record.DNSRecords {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		builder.WriteString("DNS Records:\n")
		for _, key := range keys {
			builder.WriteString(fmt.Sprintf("  %s: %s\n", key, strings.Join(record.DNSRecords[key], ", ")))
		}
	}

	if len(record.HTTPServices) > 0 {
		builder.WriteString("HTTP Services:\n")
		for _, svc := range record.HTTPServices {
			builder.WriteString(fmt.Sprintf("  %s", svc.URL))
			if svc.StatusCode > 0 {
				builder.WriteString(fmt.Sprintf(" -> %d", svc.StatusCode))
			}
			if svc.Error != "" {
				builder.WriteString(fmt.Sprintf(" (error: %s)", svc.Error))
			}
			if svc.Banner != "" {
				builder.WriteString(fmt.Sprintf(" [banner: %s]", svc.Banner))
			}
			if svc.Title != "" {
				builder.WriteString(fmt.Sprintf(" [title: %s]", svc.Title))
			}
			if svc.ScreenshotPath != "" {
				builder.WriteString(fmt.Sprintf(" [screenshot: %s]", svc.ScreenshotPath))
			}
			if svc.Snippet != "" {
				builder.WriteString(fmt.Sprintf(" [snippet: %s]", svc.Snippet))
			}
			builder.WriteString("\n")
		}
	}

	builder.WriteString("\n")

	if _, err := fmt.Fprint(w.destination, builder.String()); err != nil {
		return err
	}

	if w.buffered != nil {
		return w.buffered.Flush()
	}

	return nil
}

func flattenDNSRecords(records map[string][]string) string {
	if len(records) == 0 {
		return ""
	}

	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var parts []string
	for _, key := range keys {
		if len(records[key]) == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", key, strings.Join(records[key], ";")))
	}

	return strings.Join(parts, "|")
}

func flattenHTTPServices(services []HTTPService) string {
	if len(services) == 0 {
		return ""
	}

	parts := make([]string, 0, len(services))
	for _, service := range services {
		meta := make([]string, 0, 5)
		if service.StatusCode > 0 {
			meta = append(meta, fmt.Sprintf("status=%d", service.StatusCode))
		}
		if service.Error != "" {
			meta = append(meta, fmt.Sprintf("error=%s", service.Error))
		}
		if service.Banner != "" {
			meta = append(meta, fmt.Sprintf("banner=%s", service.Banner))
		}
		if service.Title != "" {
			meta = append(meta, fmt.Sprintf("title=%s", service.Title))
		}
		if service.ScreenshotPath != "" {
			meta = append(meta, fmt.Sprintf("screenshot=%s", service.ScreenshotPath))
		}
		if service.Snippet != "" {
			meta = append(meta, fmt.Sprintf("snippet=%s", service.Snippet))
		}

		entry := service.URL
		if len(meta) > 0 {
			entry = fmt.Sprintf("%s(%s)", entry, strings.Join(meta, ";"))
		}
		parts = append(parts, entry)
	}

	return strings.Join(parts, "|")
}

// Close flushes any buffered data and closes owned file handles.
func (w *Writer) Close() error {
	if w.csvWriter != nil {
		w.csvWriter.Flush()
		if err := w.csvWriter.Error(); err != nil {
			return err
		}
	}

	if w.buffered != nil {
		if err := w.buffered.Flush(); err != nil {
			return err
		}
	}

	if w.closer != nil {
		return w.closer.Close()
	}

	return nil
}
