package config

import "testing"

func TestValidateDefaults(t *testing.T) {
	cfg := &Config{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Mode != ModePassive {
		t.Fatalf("expected default mode passive, got %s", cfg.Mode)
	}
	if cfg.Format != FormatJSON {
		t.Fatalf("expected default format json, got %s", cfg.Format)
	}
	if cfg.Threads != 50 {
		t.Fatalf("expected default threads 50, got %d", cfg.Threads)
	}
	if cfg.AutoTune {
		t.Fatalf("expected auto-tune disabled by default")
	}
}

func TestValidateInvalidMode(t *testing.T) {
	cfg := &Config{Mode: "invalid"}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for invalid mode")
	}
}

func TestValidateSilentVerboseConflict(t *testing.T) {
	cfg := &Config{Silent: true, Verbose: true}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error when silent and verbose set")
	}
}

func TestLiveOutput(t *testing.T) {
	cfg := &Config{}
	if !cfg.LiveOutput() {
		t.Fatalf("expected live output when path empty")
	}
	cfg.OutputPath = "results.json"
	if cfg.LiveOutput() {
		t.Fatalf("expected file output when path set")
	}
}
