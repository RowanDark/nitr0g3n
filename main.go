package main

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yourusername/nitr0g3n/active/bruteforce"
	"github.com/yourusername/nitr0g3n/active/zonetransfer"
	"github.com/yourusername/nitr0g3n/config"
	"github.com/yourusername/nitr0g3n/exporter/oxg3n"
	"github.com/yourusername/nitr0g3n/filters"
	"github.com/yourusername/nitr0g3n/output"
	"github.com/yourusername/nitr0g3n/passive"
	"github.com/yourusername/nitr0g3n/passive/certtransparency"
	"github.com/yourusername/nitr0g3n/passive/hackertarget"
	"github.com/yourusername/nitr0g3n/passive/threatcrowd"
	"github.com/yourusername/nitr0g3n/passive/virustotal"
	"github.com/yourusername/nitr0g3n/probe"
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

		exporter, err := oxg3n.NewExporter(oxg3n.Options{
			Endpoint:  cfg.Export0xGenEndpoint,
			APIKey:    cfg.APIKey,
			Domain:    cfg.Domain,
			BatchSize: 100,
			Logger:    cmd.ErrOrStderr(),
		})
		if err != nil {
			return err
		}

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

		subdomainSources := make(map[string][]string)
		zoneRecords := make(map[string]map[string][]string)

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

			for subdomain, sources := range aggregation.Subdomains {
				for _, source := range sources {
					addSource(subdomainSources, subdomain, source)
				}
			}
		}

		if cfg.Mode == config.ModeActive || cfg.Mode == config.ModeAll {
			ztOpts := zonetransfer.Options{
				Domain:    cfg.Domain,
				DNSServer: cfg.DNSServer,
				Timeout:   cfg.DNSTimeout,
				Verbose:   cfg.Verbose,
				LogWriter: cmd.ErrOrStderr(),
			}

			transfers, err := zonetransfer.Run(cmd.Context(), ztOpts)
			if err != nil {
				return fmt.Errorf("active zone transfer: %w", err)
			}

			for _, transfer := range transfers {
				for hostname := range transfer.Records {
					addSource(subdomainSources, hostname, "active:zonetransfer")
				}
				mergeZoneRecords(zoneRecords, transfer.Records)
			}

			opts := bruteforce.Options{
				Domain:         cfg.Domain,
				WordlistPath:   cfg.WordlistPath,
				Permutations:   cfg.Permutations,
				DNSServer:      cfg.DNSServer,
				Timeout:        cfg.DNSTimeout,
				Workers:        cfg.Threads,
				ProgressWriter: cmd.ErrOrStderr(),
			}

			results, err := bruteforce.Run(cmd.Context(), opts)
			if err != nil {
				return fmt.Errorf("active bruteforce: %w", err)
			}

			for _, res := range results {
				addSource(subdomainSources, res.Subdomain, "active:bruteforce")
			}
		}

		if len(subdomainSources) == 0 {
			return nil
		}

		subdomains := make([]string, 0, len(subdomainSources))
		for subdomain := range subdomainSources {
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

		var wildcardProfile filters.WildcardProfile
		if cfg.FilterWildcards {
			profile, err := filters.DetectWildcard(cmd.Context(), dnsResolver, cfg.Domain, 3)
			if err != nil {
				cmd.PrintErrf("wildcard detection error: %v\n", err)
			} else {
				wildcardProfile = profile
				if cfg.Verbose && wildcardProfile.Active() {
					cmd.Println("Wildcard DNS detected; filtering matching results")
				}
			}
		}

		var httpClient *probe.Client
		if cfg.ProbeHTTP {
			httpClient = probe.NewClient(probe.Options{Timeout: cfg.DNSTimeout})
		}

		seenIPs := make(map[string]struct{})
		if !cfg.UniqueIPs {
			seenIPs = nil
		}

		for _, subdomain := range subdomains {
			resolution := resolutions[subdomain]
			if cfg.FilterWildcards && wildcardProfile.Active() && wildcardProfile.Matches(resolution) {
				if cfg.Verbose {
					cmd.Printf("Skipping wildcard subdomain: %s\n", subdomain)
				}
				continue
			}
			mergedIPs, mergedRecords := mergeResolution(resolution, zoneRecords[subdomain])
			if !cfg.ShowAll && len(mergedIPs) == 0 && len(mergedRecords) == 0 {
				continue
			}

			if resolution.Err != nil {
				cmd.PrintErrf("dns resolution %s error: %v\n", subdomain, resolution.Err)
			}

			if cfg.FilterWildcards && filters.IsCDNResponse(mergedRecords) {
				if cfg.Verbose {
					cmd.Printf("Skipping CDN-derived subdomain: %s\n", subdomain)
				}
				continue
			}

			if len(cfg.Scope) > 0 && !matchesScope(subdomain, cfg.Scope) {
				continue
			}

			if cfg.UniqueIPs {
				mergedIPs, mergedRecords = filterUniqueIPs(mergedIPs, mergedRecords, seenIPs)
				if len(mergedIPs) == 0 {
					continue
				}
			}

			record := output.Record{
				Subdomain:   subdomain,
				Source:      strings.Join(subdomainSources[subdomain], ","),
				IPAddresses: mergedIPs,
				DNSRecords:  mergedRecords,
			}
			if cfg.ProbeHTTP && httpClient != nil {
				record.HTTPServices = httpClient.Probe(cmd.Context(), subdomain)
			}
			if record.Timestamp == "" {
				record.Timestamp = time.Now().UTC().Format(time.RFC3339)
			}

			if err := writer.WriteRecord(record); err != nil {
				return fmt.Errorf("writing record: %w", err)
			}

			if exporter != nil {
				if err := exporter.AddRecord(cmd.Context(), record); err != nil {
					return fmt.Errorf("exporting to 0xg3n: %w", err)
				}
			}
		}

		if exporter != nil {
			summary, err := exporter.Flush(cmd.Context())
			if err != nil {
				return fmt.Errorf("finalising 0xg3n export: %w", err)
			}
			if summary.TotalRecords > 0 || summary.BatchesSent > 0 {
				cmd.Printf("0xg3n export complete: %d record(s) across %d batch(es)\n", summary.TotalRecords, summary.BatchesSent)
			} else {
				cmd.Println("0xg3n export complete: no records to send")
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

func addSource(m map[string][]string, subdomain, source string) {
	if strings.TrimSpace(subdomain) == "" || strings.TrimSpace(source) == "" {
		return
	}

	existing := m[subdomain]
	for _, item := range existing {
		if item == source {
			return
		}
	}

	existing = append(existing, source)
	sort.Strings(existing)
	m[subdomain] = existing
}

func mergeZoneRecords(target map[string]map[string][]string, incoming map[string]map[string][]string) {
	if len(incoming) == 0 {
		return
	}

	for hostname, records := range incoming {
		hostname = strings.TrimSpace(hostname)
		if hostname == "" {
			continue
		}

		existing := target[hostname]
		if existing == nil {
			existing = make(map[string][]string)
		}

		for recordType, values := range records {
			if len(values) == 0 {
				continue
			}
			merged := append(existing[recordType], values...)
			existing[recordType] = dedupeSortedStrings(merged)
		}

		target[hostname] = existing
	}
}

func mergeResolution(res resolver.Result, zone map[string][]string) ([]string, map[string][]string) {
	ipAddresses := append([]string(nil), res.IPAddresses...)

	var dnsRecords map[string][]string
	if len(res.DNSRecords) > 0 {
		dnsRecords = make(map[string][]string, len(res.DNSRecords))
		for recordType, values := range res.DNSRecords {
			dnsRecords[recordType] = append([]string(nil), values...)
		}
	}

	if len(zone) > 0 {
		if dnsRecords == nil {
			dnsRecords = make(map[string][]string)
		}
		for recordType, values := range zone {
			if len(values) == 0 {
				continue
			}
			dnsRecords[recordType] = dedupeSortedStrings(append(dnsRecords[recordType], values...))
			if recordType == "A" || recordType == "AAAA" {
				ipAddresses = append(ipAddresses, values...)
			}
		}
	}

	ipAddresses = dedupeSortedStrings(ipAddresses)
	if len(dnsRecords) == 0 {
		dnsRecords = nil
	}

	return ipAddresses, dnsRecords
}

func dedupeSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil
	}
	sort.Strings(result)
	return result
}

func matchesScope(subdomain string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}

	candidate := strings.ToLower(strings.TrimSpace(subdomain))
	if candidate == "" {
		return false
	}

	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}

		if strings.ContainsAny(pattern, "*?[]") {
			if ok, err := path.Match(pattern, candidate); err == nil && ok {
				return true
			}
			continue
		}

		if strings.HasPrefix(pattern, ".") {
			if strings.HasSuffix(candidate, pattern) {
				return true
			}
			continue
		}

		if strings.Contains(candidate, pattern) {
			return true
		}
	}

	return false
}

func filterUniqueIPs(ips []string, records map[string][]string, seen map[string]struct{}) ([]string, map[string][]string) {
	if len(ips) == 0 || seen == nil {
		return ips, records
	}

	filtered := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		filtered = append(filtered, ip)
	}

	if len(filtered) == 0 {
		return nil, records
	}

	if records == nil {
		return filtered, records
	}

	allowed := make(map[string]struct{}, len(filtered))
	for _, ip := range filtered {
		allowed[ip] = struct{}{}
	}

	for _, recordType := range []string{"A", "AAAA"} {
		values, ok := records[recordType]
		if !ok {
			continue
		}
		updated := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := allowed[value]; ok {
				updated = append(updated, value)
			}
		}
		if len(updated) == 0 {
			delete(records, recordType)
		} else {
			records[recordType] = updated
		}
	}

	if len(records) == 0 {
		records = nil
	}

	return filtered, records
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		if !strings.HasSuffix(err.Error(), "help requested") {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
