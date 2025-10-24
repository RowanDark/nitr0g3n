package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	level, err := ParseLevel("warn")
	if err != nil || level != LevelWarn {
		t.Fatalf("unexpected parse result: %v %v", level, err)
	}
	if _, err := ParseLevel("unknown"); err == nil {
		t.Fatalf("expected error for unknown level")
	}
}

func TestLoggerWritesToOutputs(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "app.log")
	var console bytes.Buffer

	logger, err := New(Options{Level: LevelInfo, Console: &console, FilePath: logPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer logger.Close()

	logger.Infof("starting %s", "test")
	logger.Debugf("debug message should be filtered")
	writer := logger.Writer(LevelError)
	writer.Write([]byte("first error\nsecond error\n"))

	if !strings.Contains(console.String(), "starting test") {
		t.Fatalf("console output missing log entry: %s", console.String())
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}
	contents := string(data)
	if !strings.Contains(contents, "starting test") || !strings.Contains(contents, "first error") {
		t.Fatalf("log file missing entries: %s", contents)
	}
}
