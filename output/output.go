package output

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

const (
	jsonBatchSize = 100
	queueSize     = 1024
)

type flushRequest struct {
	final bool
	done  chan error
}

// Writer serialises discovery records to stdout or a file in a configured format.
type Writer struct {
	format        config.Format
	destination   io.Writer
	closer        io.Closer
	csvWriter     *csv.Writer
	csvHeaderSent bool
	buffered      *bufio.Writer

	queue         chan Record
	flushRequests chan flushRequest
	done          chan struct{}
	wg            sync.WaitGroup

	errMu sync.Mutex
	err   error

	closed atomic.Bool

	jsonPretty     bool
	jsonBatch      []Record
	jsonBatchLimit int
	jsonArrayOpen  bool
	jsonArrayCount int

	signalChan chan os.Signal
	signalDone chan struct{}
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

	writer := &Writer{
		format:         cfg.Format,
		closer:         closer,
		jsonPretty:     cfg.JSONPretty,
		jsonBatchLimit: jsonBatchSize,
		queue:          make(chan Record, queueSize),
		flushRequests:  make(chan flushRequest, 1),
		done:           make(chan struct{}),
	}

	if !cfg.LiveOutput() {
		bufferSize := cfg.OutputBuffer
		if bufferSize <= 0 {
			bufferSize = 64 * 1024
		}
		writer.buffered = bufio.NewWriterSize(dest, bufferSize)
		dest = writer.buffered
	}

	switch cfg.Format {
	case config.FormatJSON:
		writer.destination = dest
		writer.jsonBatch = make([]Record, 0, writer.jsonBatchLimit)
	case config.FormatCSV:
		writer.csvWriter = csv.NewWriter(dest)
		writer.destination = dest
	case config.FormatTXT:
		writer.destination = dest
	default:
		return nil, fmt.Errorf("unsupported output format: %s", cfg.Format)
	}

	writer.start()
	writer.setupSignalHandling()

	return writer, nil
}

func (w *Writer) start() {
	w.wg.Add(1)
	go w.run()
}

func (w *Writer) run() {
	defer func() {
		close(w.done)
		w.wg.Done()
	}()

	for {
		select {
		case record, ok := <-w.queue:
			if !ok {
				if err := w.flushPending(true); err != nil {
					w.setErr(err)
				}
				return
			}
			if err := w.handleRecord(record); err != nil {
				w.setErr(err)
				return
			}
		case req, ok := <-w.flushRequests:
			if !ok {
				w.flushRequests = nil
				continue
			}
			err := w.flushPending(req.final)
			if req.done != nil {
				req.done <- err
			}
			if err != nil {
				w.setErr(err)
			}
		}
	}
}

func (w *Writer) handleRecord(record Record) error {
	switch w.format {
	case config.FormatJSON:
		w.jsonBatch = append(w.jsonBatch, record)
		if len(w.jsonBatch) >= w.jsonBatchLimit {
			if err := w.flushJSONBatch(false); err != nil {
				return err
			}
			if err := w.flushWriters(); err != nil {
				return err
			}
		}
		return nil
	case config.FormatCSV:
		return w.writeCSVRecord(record)
	case config.FormatTXT:
		return w.writeTXTRecord(record)
	default:
		return fmt.Errorf("unsupported output format: %s", w.format)
	}
}

func (w *Writer) flushPending(final bool) error {
	if w.format == config.FormatJSON {
		if err := w.flushJSONBatch(final); err != nil {
			return err
		}
	}
	return w.flushWriters()
}

func (w *Writer) flushWriters() error {
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

	return nil
}

// WriteRecord persists a single discovery record using the configured format.
func (w *Writer) WriteRecord(record Record) error {
	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	if record.DNSRecords == nil {
		record.DNSRecords = map[string][]string{}
	}

	if err := w.Error(); err != nil {
		return err
	}

	if w.closed.Load() {
		return fmt.Errorf("writer closed")
	}

	select {
	case w.queue <- record:
		return nil
	case <-w.done:
		return w.Error()
	}
}

func (w *Writer) setupSignalHandling() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	w.signalChan = ch
	w.signalDone = make(chan struct{})
	go func() {
		defer close(w.signalDone)
		for range ch {
			_ = w.Flush()
		}
	}()
}

// Flush drains any buffered data to the underlying destination without closing it.
func (w *Writer) Flush() error {
	if w.closed.Load() {
		return w.Error()
	}

	if err := w.Error(); err != nil {
		return err
	}

	done := make(chan error, 1)
	req := flushRequest{final: false, done: done}

	select {
	case w.flushRequests <- req:
	case <-w.done:
		return w.Error()
	}

	err := <-done
	if err != nil {
		w.setErr(err)
		return err
	}

	return nil
}

func (w *Writer) Error() error {
	w.errMu.Lock()
	defer w.errMu.Unlock()
	return w.err
}

func (w *Writer) setErr(err error) {
	if err == nil {
		return
	}
	w.errMu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.errMu.Unlock()
}

func (w *Writer) flushJSONBatch(final bool) error {
	if len(w.jsonBatch) > 0 {
		if !w.jsonArrayOpen {
			if _, err := fmt.Fprint(w.destination, "[\n"); err != nil {
				return err
			}
			w.jsonArrayOpen = true
		}

		for i, record := range w.jsonBatch {
			if w.jsonArrayCount > 0 || i > 0 {
				if _, err := fmt.Fprint(w.destination, ",\n"); err != nil {
					return err
				}
			}

			data, err := w.marshalRecord(record)
			if err != nil {
				return err
			}

			if w.jsonPretty {
				if err := w.writePrettyJSON(data); err != nil {
					return err
				}
			} else {
				if _, err := w.destination.Write(data); err != nil {
					return err
				}
			}

			w.jsonArrayCount++
		}

		w.jsonBatch = w.jsonBatch[:0]
	}

	if final {
		if !w.jsonArrayOpen {
			if _, err := fmt.Fprint(w.destination, "[]\n"); err != nil {
				return err
			}
			w.jsonArrayOpen = true
			return nil
		}

		if w.jsonArrayCount > 0 {
			if _, err := fmt.Fprint(w.destination, "\n"); err != nil {
				return err
			}
		}

		if _, err := fmt.Fprint(w.destination, "]\n"); err != nil {
			return err
		}
	}

	return nil
}

func (w *Writer) marshalRecord(record Record) ([]byte, error) {
	if w.jsonPretty {
		return json.MarshalIndent(record, "", "  ")
	}
	return json.Marshal(record)
}

func (w *Writer) writePrettyJSON(data []byte) error {
	trimmed := bytes.TrimRight(data, "\n")
	lines := bytes.Split(trimmed, []byte("\n"))
	for i, line := range lines {
		if _, err := w.destination.Write([]byte("  ")); err != nil {
			return err
		}
		if _, err := w.destination.Write(line); err != nil {
			return err
		}
		if i < len(lines)-1 {
			if _, err := w.destination.Write([]byte("\n")); err != nil {
				return err
			}
		}
	}
	return nil
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
	if !w.closed.CompareAndSwap(false, true) {
		w.wg.Wait()
		if err := w.Error(); err != nil {
			return err
		}
		if w.closer != nil {
			return w.closer.Close()
		}
		return nil
	}

	if w.signalChan != nil {
		signal.Stop(w.signalChan)
		close(w.signalChan)
		if w.signalDone != nil {
			<-w.signalDone
		}
	}

	close(w.queue)
	w.wg.Wait()

	err := w.Error()
	if w.closer != nil {
		if err != nil {
			_ = w.closer.Close()
		} else if cerr := w.closer.Close(); cerr != nil {
			err = cerr
		}
	}

	return err
}
