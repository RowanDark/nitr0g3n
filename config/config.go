package config

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// Mode constants supported by nitr0g3n.
const (
	ModeActive  = "active"
	ModePassive = "passive"
	ModeAll     = "all"
)

// Format represents an output format option.
type Format string

// Supported output format options.
const (
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
	FormatTXT  Format = "txt"
)

// Config captures all runtime configuration for the CLI.
type Config struct {
	Domain     string
	Mode       string
	OutputPath string
	Verbose    bool
	Format     Format
}

// BindFlags registers the shared command-line flags and returns a Config
// instance whose fields are populated when Cobra parses flag values.
func BindFlags(cmd *cobra.Command) *Config {
	cfg := &Config{}

	flags := cmd.PersistentFlags()
	flags.StringVarP(&cfg.Domain, "domain", "d", "", "Target domain to investigate")
	flags.StringVarP(&cfg.Mode, "mode", "m", string(ModePassive), "Enumeration mode to use (active, passive, or all)")
	flags.StringVarP(&cfg.OutputPath, "output", "o", "", "Optional file path to write results")
	flags.BoolVarP(&cfg.Verbose, "verbose", "v", false, "Enable verbose logging output")
	flags.StringVar((*string)(&cfg.Format), "format", string(FormatJSON), "Output format (json, csv, txt)")

	return cfg
}

// Validate ensures the provided configuration values meet the expected
// constraints and normalises their representation where required.
func (c *Config) Validate() error {
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	if c.Mode == "" {
		c.Mode = string(ModePassive)
	}

	switch c.Mode {
	case ModeActive, ModePassive, ModeAll:
		// valid
	default:
		return fmt.Errorf("invalid mode %q: expected %q, %q, or %q", c.Mode, ModeActive, ModePassive, ModeAll)
	}

	format := strings.ToLower(strings.TrimSpace(string(c.Format)))
	switch Format(format) {
	case FormatJSON, FormatCSV, FormatTXT:
		c.Format = Format(format)
	case "":
		c.Format = FormatJSON
	default:
		return fmt.Errorf("invalid output format %q: expected json, csv, or txt", c.Format)
	}

	return nil
}

// LiveOutput returns true when results should be sent to stdout instead of a file.
func (c *Config) LiveOutput() bool {
	return strings.TrimSpace(c.OutputPath) == ""
}
