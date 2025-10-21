package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yourusername/nitr0g3n/config"
	"github.com/yourusername/nitr0g3n/output"
	"github.com/yourusername/nitr0g3n/passive/certtransparency"
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
			ctClient := certtransparency.NewClient()
			subdomains, err := ctClient.Enumerate(cmd.Context(), cfg.Domain)
			if err != nil {
				return fmt.Errorf("certificate transparency lookup: %w", err)
			}

			for _, subdomain := range subdomains {
				record := output.Record{
					Subdomain: subdomain,
					Source:    "crt.sh",
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

func main() {
	if err := rootCmd.Execute(); err != nil {
		if !strings.HasSuffix(err.Error(), "help requested") {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
