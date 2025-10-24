package config

import (
	"fmt"
	"os"
	"strings"
	"time"

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
	Domain       string
	Mode         string
	OutputPath   string
	Verbose      bool
	Silent       bool
	ConfigPath   string
	Profile      string
	LogLevel     string
	LogFile      string
	Format       Format
	Sources      []string
	Threads      int
	DNSServer    string
	DNSTimeout   time.Duration
	Timeout      time.Duration
	ShowAll      bool
	WordlistPath string
	Permutations bool

	VirusTotalAPIKey string
	FilterWildcards  bool
	Scope            []string
	UniqueIPs        bool
	ProbeHTTP        bool

	Export0xGenEndpoint string
	APIKey              string

	RateLimit float64
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
	flags.BoolVar(&cfg.Silent, "silent", false, "Suppress non-essential console output (only emit final results)")
	flags.StringVar(&cfg.LogLevel, "log-level", "info", "Logging level (debug, info, warn, error)")
	flags.StringVar(&cfg.LogFile, "log-file", "", "Optional file path to append structured logs")
	flags.StringVar((*string)(&cfg.Format), "format", string(FormatJSON), "Output format (json, csv, txt)")
	flags.StringSliceVar(&cfg.Sources, "sources", nil, "Comma-separated list of passive sources to query")
	flags.IntVar(&cfg.Threads, "threads", 50, "Number of concurrent DNS resolution workers")
	flags.StringVar(&cfg.ConfigPath, "config", "", "Path to a YAML configuration file (defaults to .nitr0gen.yaml if present)")
	flags.StringVar(&cfg.Profile, "profile", "", "Named configuration profile to apply from the config file")
	flags.StringVar(&cfg.DNSServer, "dns-server", "", "Custom DNS server to use for resolution (host or host:port)")
	flags.DurationVar(&cfg.DNSTimeout, "dns-timeout", 5*time.Second, "Timeout for individual DNS lookups")
	flags.DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "Global timeout for network operations")
	flags.BoolVar(&cfg.ShowAll, "show-all", false, "Include subdomains without DNS records in the output")
	flags.StringVar(&cfg.WordlistPath, "wordlist", "", "Path to a custom wordlist for active bruteforce enumeration")
	flags.BoolVar(&cfg.Permutations, "permutations", true, "Enable wordlist permutations when bruteforcing")
	flags.BoolVar(&cfg.FilterWildcards, "filter-wildcards", true, "Filter wildcard DNS and generic CDN responses")
	flags.StringSliceVar(&cfg.Scope, "scope", nil, "Restrict output to subdomains matching the provided glob patterns or TLD suffixes")
	flags.BoolVar(&cfg.UniqueIPs, "unique-ips", false, "Only output subdomains that resolve to new unique IP addresses")
	flags.BoolVar(&cfg.ProbeHTTP, "probe", false, "Probe discovered subdomains over HTTP and HTTPS to capture status codes")
	flags.StringVar(&cfg.Export0xGenEndpoint, "export-0xgen", "", "0xg3n hub API endpoint to export discovered subdomains")
	flags.StringVar(&cfg.APIKey, "api-key", "", "API key used for authenticated exports (falls back to NITR0G3N_API_KEY env var)")
	flags.Float64Var(&cfg.RateLimit, "rate-limit", 0, "Maximum number of outbound requests per second (0 for unlimited)")

	return cfg
}

// Validate ensures the provided configuration values meet the expected
// constraints and normalises their representation where required.
func (c *Config) Validate() error {
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	if c.Mode == "" {
		c.Mode = string(ModePassive)
	}

	c.LogLevel = strings.ToLower(strings.TrimSpace(c.LogLevel))
	c.LogFile = strings.TrimSpace(c.LogFile)

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

	if len(c.Sources) > 0 {
		normalised := make([]string, 0, len(c.Sources))
		for _, source := range c.Sources {
			source = strings.ToLower(strings.TrimSpace(source))
			if source == "" {
				continue
			}
			normalised = append(normalised, source)
		}
		c.Sources = normalised
	}

	if len(c.Scope) > 0 {
		filtered := make([]string, 0, len(c.Scope))
		for _, pattern := range c.Scope {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			filtered = append(filtered, pattern)
		}
		c.Scope = filtered
	}

	if c.VirusTotalAPIKey == "" {
		c.VirusTotalAPIKey = strings.TrimSpace(os.Getenv("NITR0G3N_VIRUSTOTAL_API_KEY"))
	}
	if c.VirusTotalAPIKey == "" {
		c.VirusTotalAPIKey = strings.TrimSpace(os.Getenv("VIRUSTOTAL_API_KEY"))
	}

	if c.APIKey == "" {
		c.APIKey = strings.TrimSpace(os.Getenv("NITR0G3N_API_KEY"))
	}

	c.Export0xGenEndpoint = strings.TrimSpace(c.Export0xGenEndpoint)
	c.APIKey = strings.TrimSpace(c.APIKey)

	if c.Threads <= 0 {
		c.Threads = 50
	}

	c.DNSServer = strings.TrimSpace(c.DNSServer)
	c.WordlistPath = strings.TrimSpace(c.WordlistPath)

	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}

	if c.DNSTimeout <= 0 {
		c.DNSTimeout = c.Timeout
	}

	if c.Silent && c.Verbose {
		return fmt.Errorf("--silent cannot be combined with --verbose")
	}

	return nil
}

// LiveOutput returns true when results should be sent to stdout instead of a file.
func (c *Config) LiveOutput() bool {
	return strings.TrimSpace(c.OutputPath) == ""
}
