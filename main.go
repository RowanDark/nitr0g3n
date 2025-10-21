package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	domain  string
	mode    string
	output  string
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:     "nitro",
	Aliases: []string{"nitr0"},
	Short:   "nitr0g3n is a reconnaissance toolkit for domain intelligence.",
	Long: `nitr0g3n is an extensible reconnaissance toolkit focused on domain intelligence.
It provides active and passive discovery workflows to help analysts profile
infrastructure quickly and accurately.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if mode != "active" && mode != "passive" {
			return fmt.Errorf("invalid mode %q: expected \"active\" or \"passive\"", mode)
		}

		if verbose {
			cmd.Println("Verbose output enabled")
			cmd.Printf("Target domain: %s\n", domain)
			cmd.Printf("Mode: %s\n", mode)
			if output != "" {
				cmd.Printf("Results will be written to: %s\n", output)
			}
		} else if !cmd.Flags().Changed("domain") && !cmd.Flags().Changed("output") && !cmd.Flags().Changed("mode") {
			return cmd.Help()
		}

		if domain == "" {
			cmd.Println("No target domain specified. Use --domain to set a target or see --help for more details.")
		}

		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&domain, "domain", "d", "", "Target domain to investigate")
	rootCmd.PersistentFlags().StringVarP(&mode, "mode", "m", "passive", "Enumeration mode to use (active or passive)")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "Optional file path to write results")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging output")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		if !strings.HasSuffix(err.Error(), "help requested") {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
