package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

const defaultConfigFilename = ".nitr0gen.yaml"

type fileConfig struct {
	Profiles map[string]profileSettings `yaml:"profiles"`
}

type profileSettings struct {
	Domain              *string        `yaml:"domain"`
	Mode                *string        `yaml:"mode"`
	OutputPath          *string        `yaml:"output"`
	DiffPath            *string        `yaml:"diff"`
	Verbose             *bool          `yaml:"verbose"`
	Silent              *bool          `yaml:"silent"`
	LogLevel            *string        `yaml:"log_level"`
	LogFile             *string        `yaml:"log_file"`
	Format              *string        `yaml:"format"`
	JSONPretty          *bool          `yaml:"json_pretty"`
	Sources             *StringSlice   `yaml:"sources"`
	Threads             *int           `yaml:"threads"`
	AutoTune            *bool          `yaml:"auto_tune"`
	DNSServer           *string        `yaml:"dns_server"`
	DNSTimeout          *time.Duration `yaml:"dns_timeout"`
	DNSCache            *bool          `yaml:"dns_cache"`
	DNSCacheSize        *int           `yaml:"dns_cache_size"`
	Timeout             *time.Duration `yaml:"timeout"`
	ShowAll             *bool          `yaml:"show_all"`
	WordlistPath        *string        `yaml:"wordlist"`
	Permutations        *bool          `yaml:"permutations"`
	PermutationThreads  *int           `yaml:"permutation_threads"`
	VirusTotalAPIKey    *string        `yaml:"virustotal_api_key"`
	FilterWildcards     *bool          `yaml:"filter_wildcards"`
	Scope               *StringSlice   `yaml:"scope"`
	UniqueIPs           *bool          `yaml:"unique_ips"`
	ProbeHTTP           *bool          `yaml:"probe"`
	ScreenshotDir       *string        `yaml:"screenshot_dir"`
	ParallelSources     *bool          `yaml:"parallel_sources"`
	Export0xGenEndpoint *string        `yaml:"export_0xgen"`
	APIKey              *string        `yaml:"api_key"`
	RateLimit           *float64       `yaml:"rate_limit"`
	GCPercent           *int           `yaml:"gc_percent"`
}

type StringSlice []string

func (s *StringSlice) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var str string
		if err := value.Decode(&str); err != nil {
			return err
		}
		str = strings.TrimSpace(str)
		if str == "" {
			*s = nil
			return nil
		}
		*s = []string{str}
		return nil
	case yaml.SequenceNode:
		var raw []string
		if err := value.Decode(&raw); err != nil {
			return err
		}
		cleaned := make([]string, 0, len(raw))
		for _, item := range raw {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			cleaned = append(cleaned, item)
		}
		*s = cleaned
		return nil
	default:
		return fmt.Errorf("unsupported YAML type %s for string slice", value.ShortTag())
	}
}

func (s *StringSlice) ToSlice() []string {
	if s == nil {
		return nil
	}
	dup := make([]string, len(*s))
	copy(dup, *s)
	return dup
}

// ApplyProfile loads and applies the requested configuration profile to cfg.
// Command-line flag overrides take precedence over profile values.
func ApplyProfile(cfg *Config, cmd *cobra.Command) error {
	path, err := resolveConfigPath(cfg.ConfigPath)
	if err != nil {
		return fmt.Errorf("locating config file: %w", err)
	}

	if path == "" {
		if cfg.Profile != "" {
			return fmt.Errorf("profile %q requested but no %s file was found", cfg.Profile, defaultConfigFilename)
		}
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config file %s: %w", path, err)
	}

	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if len(fc.Profiles) == 0 {
		if cfg.Profile != "" {
			return fmt.Errorf("profile %q not found in %s", cfg.Profile, path)
		}
		return nil
	}

	profileName := cfg.Profile
	if profileName == "" {
		if _, ok := fc.Profiles["default"]; ok {
			profileName = "default"
		}
	}

	if profileName == "" {
		return nil
	}

	profile, ok := fc.Profiles[profileName]
	if !ok {
		return fmt.Errorf("profile %q not found in %s", profileName, path)
	}

	applyProfileSettings(cfg, &profile, cmd)
	cfg.ConfigPath = path
	return nil
}

func applyProfileSettings(cfg *Config, profile *profileSettings, cmd *cobra.Command) {
	flags := cmd.Flags()

	if profile.Domain != nil && !flagChanged(flags, "domain") {
		cfg.Domain = strings.TrimSpace(*profile.Domain)
	}
	if profile.Mode != nil && !flagChanged(flags, "mode") {
		cfg.Mode = strings.TrimSpace(*profile.Mode)
	}
	if profile.OutputPath != nil && !flagChanged(flags, "output") {
		cfg.OutputPath = strings.TrimSpace(*profile.OutputPath)
	}
	if profile.DiffPath != nil && !flagChanged(flags, "diff") {
		cfg.DiffPath = strings.TrimSpace(*profile.DiffPath)
	}
	if profile.Verbose != nil && !flagChanged(flags, "verbose") {
		cfg.Verbose = *profile.Verbose
	}
	if profile.Silent != nil && !flagChanged(flags, "silent") {
		cfg.Silent = *profile.Silent
	}
	if profile.LogLevel != nil && !flagChanged(flags, "log-level") {
		cfg.LogLevel = strings.TrimSpace(*profile.LogLevel)
	}
	if profile.LogFile != nil && !flagChanged(flags, "log-file") {
		cfg.LogFile = strings.TrimSpace(*profile.LogFile)
	}
	if profile.Format != nil && !flagChanged(flags, "format") {
		cfg.Format = Format(strings.TrimSpace(*profile.Format))
	}
	if profile.JSONPretty != nil && !flagChanged(flags, "json-pretty") {
		cfg.JSONPretty = *profile.JSONPretty
	}
	if profile.Sources != nil && !flagChanged(flags, "sources") {
		cfg.Sources = profile.Sources.ToSlice()
	}
	if profile.Threads != nil && !flagChanged(flags, "threads") {
		cfg.Threads = *profile.Threads
	}
	if profile.AutoTune != nil && !flagChanged(flags, "auto-tune") {
		cfg.AutoTune = *profile.AutoTune
	}
	if profile.DNSServer != nil && !flagChanged(flags, "dns-server") {
		cfg.DNSServer = strings.TrimSpace(*profile.DNSServer)
	}
	if profile.DNSTimeout != nil && !flagChanged(flags, "dns-timeout") {
		cfg.DNSTimeout = *profile.DNSTimeout
	}
	if profile.DNSCache != nil && !flagChanged(flags, "dns-cache") {
		cfg.DNSCache = *profile.DNSCache
	}
	if profile.DNSCacheSize != nil && !flagChanged(flags, "dns-cache-size") {
		cfg.DNSCacheSize = *profile.DNSCacheSize
	}
	if profile.Timeout != nil && !flagChanged(flags, "timeout") {
		cfg.Timeout = *profile.Timeout
	}
	if profile.ShowAll != nil && !flagChanged(flags, "show-all") {
		cfg.ShowAll = *profile.ShowAll
	}
	if profile.WordlistPath != nil && !flagChanged(flags, "wordlist") {
		cfg.WordlistPath = strings.TrimSpace(*profile.WordlistPath)
	}
	if profile.Permutations != nil && !flagChanged(flags, "permutations") {
		cfg.Permutations = *profile.Permutations
	}
	if profile.PermutationThreads != nil && !flagChanged(flags, "permutation-threads") {
		cfg.PermutationThreads = *profile.PermutationThreads
	}
	if profile.VirusTotalAPIKey != nil && !flagChanged(flags, "virustotal-api-key") {
		cfg.VirusTotalAPIKey = strings.TrimSpace(*profile.VirusTotalAPIKey)
	}
	if profile.FilterWildcards != nil && !flagChanged(flags, "filter-wildcards") {
		cfg.FilterWildcards = *profile.FilterWildcards
	}
	if profile.Scope != nil && !flagChanged(flags, "scope") {
		cfg.Scope = profile.Scope.ToSlice()
	}
	if profile.UniqueIPs != nil && !flagChanged(flags, "unique-ips") {
		cfg.UniqueIPs = *profile.UniqueIPs
	}
	if profile.ProbeHTTP != nil && !flagChanged(flags, "probe") {
		cfg.ProbeHTTP = *profile.ProbeHTTP
	}
	if profile.ScreenshotDir != nil && !flagChanged(flags, "screenshot-dir") {
		cfg.ScreenshotDir = strings.TrimSpace(*profile.ScreenshotDir)
	}
	if profile.ParallelSources != nil && !flagChanged(flags, "parallel-sources") {
		cfg.ParallelSources = *profile.ParallelSources
	}
	if profile.Export0xGenEndpoint != nil && !flagChanged(flags, "export-0xgen") {
		cfg.Export0xGenEndpoint = strings.TrimSpace(*profile.Export0xGenEndpoint)
	}
	if profile.APIKey != nil && !flagChanged(flags, "api-key") {
		cfg.APIKey = strings.TrimSpace(*profile.APIKey)
	}
	if profile.RateLimit != nil && !flagChanged(flags, "rate-limit") {
		cfg.RateLimit = *profile.RateLimit
	}
	if profile.GCPercent != nil && !flagChanged(flags, "gc-percent") {
		cfg.GCPercent = *profile.GCPercent
	}
}

func resolveConfigPath(explicit string) (string, error) {
	if explicit != "" {
		abs := explicit
		if !filepath.IsAbs(abs) {
			if resolved, err := filepath.Abs(explicit); err == nil {
				abs = resolved
			}
		}
		if _, err := os.Stat(abs); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return "", err
			}
			return "", fmt.Errorf("stat %s: %w", abs, err)
		}
		return abs, nil
	}

	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, defaultConfigFilename)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	} else {
		return "", fmt.Errorf("getwd: %w", err)
	}

	if home, err := os.UserHomeDir(); err == nil {
		candidate := filepath.Join(home, defaultConfigFilename)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", nil
}

func flagChanged(flags *pflag.FlagSet, name string) bool {
	if flags == nil {
		return false
	}
	flag := flags.Lookup(name)
	if flag == nil {
		return false
	}
	return flag.Changed
}
