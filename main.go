package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yourusername/nitr0g3n/config"
	"github.com/yourusername/nitr0g3n/output"
	"github.com/yourusername/nitr0g3n/passive"
	"github.com/yourusername/nitr0g3n/passive/certtransparency"
	"github.com/yourusername/nitr0g3n/passive/hackertarget"
	"github.com/yourusername/nitr0g3n/passive/threatcrowd"
	"github.com/yourusername/nitr0g3n/passive/virustotal"
	"github.com/yourusername/nitr0g3n/resolver"
)

var cfg *config.Config

var rootCmd = &cobra.Command{
	Use:     "nitro",
	Aliases: []string{"nitr0"},
	Short:   "nitr0g3n is a reconnaissance toolkit for domain intelligence.",
	Long: `nitr0g3n is an extensible reconnaissance toolkit focused on domain intelligence.
It provides active and passive discovery workflows to help analysts profile
infrastructure quickly and accurately.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := cfg.Validate(); err != nil {
			return err
		}

		writer, err := output.NewWriter(cfg)
		if err != nil {
			return err
		}
		defer writer.Close()

		if cfg.Verbose {
			cmd.Println("Verbose output enabled")
			cmd.Printf("Target domain: %s\n", cfg.Domain)
			cmd.Printf("Mode: %s\n", cfg.Mode)
			cmd.Printf("Output format: %s\n", cfg.Format)
			if !cfg.LiveOutput() {
				cmd.Printf("Results will be written to: %s\n", cfg.OutputPath)
			} else {
				cmd.Println("Live output enabled; results will be printed to stdout")
			}
		} else if !cmd.Flags().Changed("domain") && !cmd.Flags().Changed("output") && !cmd.Flags().Changed("mode") && !cmd.Flags().Changed("format") {
			return cmd.Help()
		}

		if cfg.Domain == "" {
			cmd.Println("No target domain specified. Use --domain to set a target or see --help for more details.")
			return nil
		}

		if cfg.Mode == config.ModePassive || cfg.Mode == config.ModeAll {
			passiveSources, err := buildPassiveSources(cfg)
			if err != nil {
				return err
			}

			aggregation := passive.Aggregate(cmd.Context(), cfg.Domain, passiveSources)
			if len(aggregation.Errors) > 0 {
				for name, sourceErr := range aggregation.Errors {
					cmd.PrintErrf("passive source %s error: %v\n", name, sourceErr)
				}
			}

			if len(aggregation.Subdomains) == 0 {
				return nil
			}

			subdomains := make([]string, 0, len(aggregation.Subdomains))
			for subdomain := range aggregation.Subdomains {
				subdomains = append(subdomains, subdomain)
			}
			sort.Strings(subdomains)

			resolveOpts := resolver.Options{
				Server:  cfg.DNSServer,
				Timeout: cfg.DNSTimeout,
			}
			dnsResolver, err := resolver.New(resolveOpts)
			if err != nil {
				return fmt.Errorf("configuring resolver: %w", err)
			}

			resolutions := dnsResolver.ResolveAll(cmd.Context(), subdomains, cfg.Threads)

			for _, subdomain := range subdomains {
				resolution := resolutions[subdomain]
				if !cfg.ShowAll && len(resolution.IPAddresses) == 0 && len(resolution.DNSRecords) == 0 {
					continue
				}

				if resolution.Err != nil {
					cmd.PrintErrf("dns resolution %s error: %v\n", subdomain, resolution.Err)
				}

				record := output.Record{
					Subdomain:   subdomain,
					Source:      strings.Join(aggregation.Subdomains[subdomain], ","),
					IPAddresses: resolution.IPAddresses,
					DNSRecords:  resolution.DNSRecords,
				}
				if err := writer.WriteRecord(record); err != nil {
					return fmt.Errorf("writing record: %w", err)
				}
			}
		}

		return nil
	},
}

func init() {
	cfg = config.BindFlags(rootCmd)
}

func buildPassiveSources(cfg *config.Config) ([]passive.Source, error) {
	ctClient := certtransparency.NewClient()
	htClient := hackertarget.NewClient()
	tcClient := threatcrowd.NewClient()
	vtClient := virustotal.NewClient(cfg.VirusTotalAPIKey)

	available := map[string]passive.Source{
		"crtsh":            ctClient,
		"crt.sh":           ctClient,
		"certtransparency": ctClient,
		"hackertarget":     htClient,
		"threatcrowd":      tcClient,
		"virustotal":       vtClient,
		"vt":               vtClient,
	}

	defaultOrder := []string{"crtsh", "hackertarget", "threatcrowd", "virustotal"}

	if len(cfg.Sources) == 0 {
		return selectSources(defaultOrder, available)
	}

	return selectSources(cfg.Sources, available)
}

func selectSources(requested []string, available map[string]passive.Source) ([]passive.Source, error) {
	selected := make([]passive.Source, 0, len(requested))
	seen := make(map[string]struct{})

	for _, name := range requested {
		canonical := strings.ToLower(strings.TrimSpace(name))
		if canonical == "" {
			continue
		}

		source, ok := available[canonical]
		if !ok {
			return nil, fmt.Errorf("unknown passive source %q", name)
		}

		sourceName := source.Name()
		if _, exists := seen[sourceName]; exists {
			continue
		}

		selected = append(selected, source)
		seen[sourceName] = struct{}{}
	}

	if len(selected) == 0 {
		return nil, fmt.Errorf("no passive sources selected")
	}

	return selected, nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		if !strings.HasSuffix(err.Error(), "help requested") {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
