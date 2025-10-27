package output

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yourusername/nitr0g3n/config"
)

func TestJSONWriter(t *testing.T) {
	cfg := &config.Config{Format: config.FormatJSON, OutputPath: filepath.Join(t.TempDir(), "out.json")}
	writer, err := NewWriter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	record := Record{Subdomain: "www.example.com", Source: "test"}
	if err := writer.WriteRecord(record); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	data, err := os.ReadFile(cfg.OutputPath)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}
	var decoded []Record
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decoding json: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected single record, got %d", len(decoded))
	}
	if decoded[0].Timestamp == "" {
		t.Fatalf("expected timestamp to be populated")
	}
}

func TestJSONWriterPretty(t *testing.T) {
	cfg := &config.Config{Format: config.FormatJSON, OutputPath: filepath.Join(t.TempDir(), "out.json"), JSONPretty: true}
	writer, err := NewWriter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := writer.WriteRecord(Record{Subdomain: "pretty.example.com", Source: "test"}); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	data, err := os.ReadFile(cfg.OutputPath)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}
	if !strings.Contains(string(data), "\n    \"subdomain\"") {
		t.Fatalf("expected pretty-printed json, got: %s", string(data))
	}
}

func TestCSVWriter(t *testing.T) {
	cfg := &config.Config{Format: config.FormatCSV, OutputPath: filepath.Join(t.TempDir(), "out.csv")}
	writer, err := NewWriter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	record := Record{
		Subdomain:   "api.example.com",
		Source:      "test",
		IPAddresses: []string{"192.0.2.1"},
		DNSRecords:  map[string][]string{"A": []string{"192.0.2.1"}},
		Change:      "new",
	}
	if err := writer.WriteRecord(record); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	file, err := os.Open(cfg.OutputPath)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	defer file.Close()

	csvReader := csv.NewReader(file)
	rows, err := csvReader.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected header and row, got %d", len(rows))
	}
	if len(rows[0]) != 7 || len(rows[1]) != 7 {
		t.Fatalf("expected 7 columns including change metadata")
	}
}

func TestTXTWriter(t *testing.T) {
	cfg := &config.Config{Format: config.FormatTXT, OutputPath: filepath.Join(t.TempDir(), "out.txt")}
	writer, err := NewWriter(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	record := Record{
		Subdomain:    "login.example.com",
		Source:       "test",
		IPAddresses:  []string{"198.51.100.5"},
		DNSRecords:   map[string][]string{"A": []string{"198.51.100.5"}},
		HTTPServices: []HTTPService{{URL: "https://login.example.com", StatusCode: 200, Banner: "nginx", Title: "Login"}},
	}
	if err := writer.WriteRecord(record); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	data, err := os.ReadFile(cfg.OutputPath)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "Subdomain: login.example.com") {
		t.Fatalf("unexpected txt output: %s", content)
	}
	if !strings.Contains(content, "banner: nginx") || !strings.Contains(content, "title: Login") {
		t.Fatalf("expected banner and title metadata in txt output: %s", content)
	}
}

func TestFlattenHelpers(t *testing.T) {
	dns := map[string][]string{"A": []string{"192.0.2.1"}, "MX": []string{"10 mail.example.com"}}
	if got := flattenDNSRecords(dns); got == "" || !strings.Contains(got, "A=192.0.2.1") {
		t.Fatalf("unexpected dns flatten result: %s", got)
	}

	services := []HTTPService{{URL: "https://example.com", StatusCode: 200, Banner: "nginx"}, {URL: "http://example.com", Error: "timeout"}}
	if got := flattenHTTPServices(services); !strings.Contains(got, "https://example.com(status=200;banner=nginx)") || !strings.Contains(got, "http://example.com(error=timeout)") {
		t.Fatalf("unexpected http flatten result: %s", got)
	}
}

func TestLoadRecords(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "records.json")
	file, err := os.Create(tmp)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	encoder := json.NewEncoder(file)
	records := []Record{{Subdomain: "a.example.com"}, {Subdomain: "b.example.com"}}
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			t.Fatalf("encode record: %v", err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	loaded, err := LoadRecords(tmp)
	if err != nil {
		t.Fatalf("load records: %v", err)
	}
	if len(loaded) != len(records) {
		t.Fatalf("expected %d record(s), got %d", len(records), len(loaded))
	}
}

func TestLoadRecordsJSONArray(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "records.json")
	records := []Record{{Subdomain: "array.example.com"}, {Subdomain: "array2.example.com"}}
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("marshal records: %v", err)
	}
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	loaded, err := LoadRecords(tmp)
	if err != nil {
		t.Fatalf("load records: %v", err)
	}
	if len(loaded) != len(records) {
		t.Fatalf("expected %d record(s), got %d", len(records), len(loaded))
	}
}
