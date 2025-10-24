package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func TestStringSliceUnmarshalScalar(t *testing.T) {
	var slice StringSlice
	if err := slice.UnmarshalYAML(newScalarNode(" crtsh ")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(slice) != 1 || slice[0] != "crtsh" {
		t.Fatalf("expected [crtsh], got %#v", []string(slice))
	}
}

func TestStringSliceUnmarshalSequence(t *testing.T) {
	var slice StringSlice
	if err := slice.UnmarshalYAML(newSequenceNode(" crtsh ", "", "dnsdumpster")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []string{"crtsh", "dnsdumpster"}
	if len(slice) != len(expected) {
		t.Fatalf("expected %d entries, got %d", len(expected), len(slice))
	}
	for i, v := range expected {
		if slice[i] != v {
			t.Fatalf("expected element %d to be %q, got %q", i, v, slice[i])
		}
	}
}

func TestApplyProfileLoadsNamedProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeConfig(t, path, `profiles:
  quick:
    mode: passive
    sources:
      - crtsh
    threads: 25
    verbose: true
`)

	cmd := &cobra.Command{Use: "test"}
	cfg := BindFlags(cmd)
	cfg.ConfigPath = path
	cfg.Profile = "quick"
	if err := cmd.ParseFlags([]string{}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	if err := ApplyProfile(cfg, cmd); err != nil {
		t.Fatalf("ApplyProfile error: %v", err)
	}

	if cfg.Mode != "passive" {
		t.Fatalf("expected mode passive, got %s", cfg.Mode)
	}
	if len(cfg.Sources) != 1 || cfg.Sources[0] != "crtsh" {
		t.Fatalf("expected sources [crtsh], got %#v", cfg.Sources)
	}
	if cfg.Threads != 25 {
		t.Fatalf("expected threads 25, got %d", cfg.Threads)
	}
	if !cfg.Verbose {
		t.Fatalf("expected verbose true")
	}
}

func TestApplyProfileRespectsFlagOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeConfig(t, path, `profiles:
  quick:
    mode: passive
    threads: 10
`)
	cmd := &cobra.Command{Use: "test"}
	cfg := BindFlags(cmd)
	cfg.ConfigPath = path
	cfg.Profile = "quick"
	if err := cmd.ParseFlags([]string{}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if err := cmd.Flags().Set("threads", "77"); err != nil {
		t.Fatalf("set threads flag: %v", err)
	}

	if err := ApplyProfile(cfg, cmd); err != nil {
		t.Fatalf("ApplyProfile error: %v", err)
	}

	if cfg.Threads != 77 {
		t.Fatalf("expected threads to remain 77, got %d", cfg.Threads)
	}
	if cfg.Mode != "passive" {
		t.Fatalf("expected mode passive, got %s", cfg.Mode)
	}
}

func TestApplyProfileUsesDefaultProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeConfig(t, path, `profiles:
  default:
    mode: all
    permutations: false
`)
	cmd := &cobra.Command{Use: "test"}
	cfg := BindFlags(cmd)
	cfg.ConfigPath = path
	if err := cmd.ParseFlags([]string{}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	if err := ApplyProfile(cfg, cmd); err != nil {
		t.Fatalf("ApplyProfile error: %v", err)
	}

	if cfg.Mode != "all" {
		t.Fatalf("expected mode all, got %s", cfg.Mode)
	}
	if cfg.Permutations {
		t.Fatalf("expected permutations false")
	}
}

func TestApplyProfileMissingConfigReturnsError(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cfg := BindFlags(cmd)
	cfg.ConfigPath = filepath.Join(t.TempDir(), "missing.yaml")
	cfg.Profile = "quick"
	if err := cmd.ParseFlags([]string{}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	if err := ApplyProfile(cfg, cmd); err == nil {
		t.Fatalf("expected error for missing config file")
	}
}

func writeConfig(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func newScalarNode(values ...string) *yaml.Node {
	if len(values) == 0 {
		return &yaml.Node{Kind: yaml.ScalarNode}
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Value: values[0]}
}

func newSequenceNode(values ...string) *yaml.Node {
	node := &yaml.Node{Kind: yaml.SequenceNode}
	for _, v := range values {
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: v})
	}
	return node
}
