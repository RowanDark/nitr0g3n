package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/yourusername/nitr0g3n/active/bruteforce"
	"github.com/yourusername/nitr0g3n/active/zonetransfer"
	"github.com/yourusername/nitr0g3n/config"
	"github.com/yourusername/nitr0g3n/exporter/oxg3n"
	"github.com/yourusername/nitr0g3n/filters"
	"github.com/yourusername/nitr0g3n/logging"
	"github.com/yourusername/nitr0g3n/netutil"
	"github.com/yourusername/nitr0g3n/notifier/webhook"
	"github.com/yourusername/nitr0g3n/output"
	"github.com/yourusername/nitr0g3n/passive"
	"github.com/yourusername/nitr0g3n/passive/certtransparency"
	"github.com/yourusername/nitr0g3n/passive/hackertarget"
	"github.com/yourusername/nitr0g3n/passive/threatcrowd"
	"github.com/yourusername/nitr0g3n/passive/virustotal"
	"github.com/yourusername/nitr0g3n/probe"
	"github.com/yourusername/nitr0g3n/ratelimit"
	"github.com/yourusername/nitr0g3n/resolver"
	"github.com/yourusername/nitr0g3n/stats"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

var cfg *config.Config

var rootCmd = &cobra.Command{
	Use:     "nitro",
	Aliases: []string{"nitr0"},
	Short:   "nitr0g3n is a reconnaissance toolkit for domain intelligence.",
	Long: `nitr0g3n is an extensible reconnaissance toolkit focused on domain intelligence.
It provides active and passive discovery workflows to help analysts profile
infrastructure quickly and accurately.`,
	RunE: func(cmd *cobra.Command, args []string) (runErr error) {
		showVersion, err := cmd.Flags().GetBool("version")
		if err != nil {
			return err
		}
		if showVersion {
			fmt.Fprintf(cmd.OutOrStdout(), "nitr0g3n version: %s\n", version)
			fmt.Fprintf(cmd.OutOrStdout(), "commit: %s\n", commit)
			fmt.Fprintf(cmd.OutOrStdout(), "built: %s\n", date)
			return nil
		}

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		if err := config.ApplyProfile(cfg, cmd); err != nil {
			return err
		}

		if err := cfg.Validate(); err != nil {
			return err
		}

		previousGC := debug.SetGCPercent(cfg.GCPercent)
		defer debug.SetGCPercent(previousGC)

		levelName := cfg.LogLevel
		if cfg.Verbose && !cmd.Flags().Changed("log-level") {
			levelName = "debug"
		}

		level, err := logging.ParseLevel(levelName)
		if err != nil {
			return err
		}

		console := cmd.ErrOrStderr()
		if cfg.Silent {
			console = io.Discard
		}

		logger, err := logging.New(logging.Options{Level: level, Console: console, FilePath: cfg.LogFile})
		if err != nil {
			return err
		}
		defer logger.Close()

		verboseEnabled := cfg.Verbose || level <= logging.LevelDebug

		targets, err := gatherTargets(cmd.InOrStdin(), cfg.Domain)
		if err != nil {
			return err
		}

		if len(targets) == 0 {
			logger.Warnf("No target domain specified. Use --domain to set a target or pipe targets via stdin.")
			if !verboseEnabled {
				_ = cmd.Help()
			}
			return nil
		}

		if cfg.Watch && len(targets) > 1 {
			return fmt.Errorf("--watch can only be used with a single target")
		}

		writer, err := output.NewWriter(cfg)
		if err != nil {
			return err
		}
		defer writer.Close()

		if cfg.LogFile != "" {
			logger.Infof("File logging enabled: %s", cfg.LogFile)
		}

		for _, target := range targets {
			domain := strings.TrimSpace(target)
			if domain == "" {
				continue
			}

			domainCfg := *cfg
			domainCfg.Domain = domain

			if err := runDomain(ctx, &domainCfg, logger, writer, verboseEnabled); err != nil {
				return err
			}

			if ctx.Err() != nil {
				break
			}
		}

		return nil
	},
}

func init() {
	cfg = config.BindFlags(rootCmd)
	rootCmd.PersistentFlags().BoolP("version", "V", false, "Show nitr0g3n version information and exit")
}

func gatherTargets(input io.Reader, domain string) ([]string, error) {
	trimmed := strings.TrimSpace(domain)
	if trimmed != "" {
		return []string{trimmed}, nil
	}

	return readTargetsFromStdin(input)
}

func readTargetsFromStdin(r io.Reader) ([]string, error) {
	file, ok := r.(*os.File)
	if ok {
		if stat, err := file.Stat(); err == nil {
			if stat.Mode()&os.ModeCharDevice != 0 {
				return nil, nil
			}
		}
	}

	scanner := bufio.NewScanner(r)
	targets := make([]string, 0)
	seen := make(map[string]struct{})

	for scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" {
			continue
		}
		lower := strings.ToLower(value)
		if _, exists := seen[lower]; exists {
			continue
		}
		seen[lower] = struct{}{}
		targets = append(targets, value)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}

func runDomain(ctx context.Context, cfg *config.Config, logger *logging.Logger, writer *output.Writer, verboseEnabled bool) error {
	limiter := ratelimit.New(cfg.RateLimit)
	monitorCancel := func() {}
	if limiter != nil {
		monitorCtx, cancel := context.WithCancel(ctx)
		monitorCancel = cancel
		startRateLimitMonitor(monitorCtx, limiter, logger)
	}
	defer monitorCancel()
	httpClient := netutil.NewHTTPClient(cfg.Timeout, limiter)

	notifier, err := webhook.New(webhook.Options{
		Endpoint: cfg.WebhookURL,
		Secret:   cfg.WebhookSecret,
		Domain:   cfg.Domain,
		Client:   httpClient,
		Logger:   logger.Writer(logging.LevelInfo),
	})
	if err != nil {
		return err
	}

	var diffBaseline map[string]output.Record
	if cfg.DiffPath != "" {
		previous, err := output.LoadRecords(cfg.DiffPath)
		if err != nil {
			logger.Warnf("Unable to load diff baseline %s: %v", cfg.DiffPath, err)
		} else {
			diffBaseline = make(map[string]output.Record, len(previous))
			for _, rec := range previous {
				normalized := normalizeDiffRecord(rec)
				if normalized.Subdomain == "" {
					continue
				}
				diffBaseline[normalized.Subdomain] = normalized
			}
			logger.Infof("Loaded %d baseline record(s) from %s", len(diffBaseline), cfg.DiffPath)
		}
	}

	var watchKnown map[string]output.Record
	if cfg.Watch {
		watchKnown = make(map[string]output.Record)
	}

	iteration := 0
	for {
		iteration++

		diffRemaining := cloneDiffBaseline(diffBaseline)
		diffStats := diffSummary{}

		if cfg.Watch {
			logger.Infof("Watch iteration %d: enumerating domain %s using %s mode (format=%s)", iteration, cfg.Domain, cfg.Mode, cfg.Format)
		} else {
			logger.Infof("Enumerating domain %s using %s mode (format=%s)", cfg.Domain, cfg.Mode, cfg.Format)
		}
		if iteration == 1 {
			if !cfg.LiveOutput() {
				logger.Infof("Results will be written to %s", cfg.OutputPath)
			} else {
				logger.Infof("Live output enabled; results will be printed to stdout")
			}
		}

		exporter, err := oxg3n.NewExporter(oxg3n.Options{
			Endpoint:  cfg.Export0xGenEndpoint,
			APIKey:    cfg.APIKey,
			Domain:    cfg.Domain,
			Client:    httpClient,
			BatchSize: 100,
			Logger:    logger.Writer(logging.LevelInfo),
		})
		if err != nil {
			return err
		}

		tracker := stats.NewTracker(stats.Options{Logger: logger})
		tracker.Start(ctx.Done())

		iterErr := runCycle(ctx, cfg, logger, limiter, httpClient, writer, exporter, diffBaseline, diffRemaining, &diffStats, watchKnown, notifier, tracker, verboseEnabled)
		snapshot := tracker.Stop()
		if iterErr == nil {
			logScanSummary(logger, cfg, snapshot)
		}

		if iterErr != nil {
			return iterErr
		}

		if diffBaseline != nil && diffRemaining != nil {
			if remaining := len(diffRemaining); remaining > 0 {
				diffStats.removed = make([]string, 0, remaining)
				for subdomain := range diffRemaining {
					diffStats.removed = append(diffStats.removed, subdomain)
				}
				sort.Strings(diffStats.removed)
				diffStats.removedCount = remaining
			}

			logger.Infof("Diff summary: %d new, %d updated, %d removed compared to %s", diffStats.added, diffStats.updated, diffStats.removedCount, cfg.DiffPath)
			if diffStats.removedCount > 0 {
				preview := diffStats.removed
				if len(preview) > 10 {
					preview = preview[:10]
				}
				logger.Infof("Removed subdomains: %s", strings.Join(preview, ", "))
				if diffStats.removedCount > len(preview) {
					logger.Infof("Removed subdomains truncated; %d additional entries omitted", diffStats.removedCount-len(preview))
				}
			}
		}

		if !cfg.Watch {
			return nil
		}

		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}

		logger.Infof("Watch iteration %d complete; sleeping for %s", iteration, cfg.WatchInterval)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(cfg.WatchInterval):
		}
	}
}

func runCycle(ctx context.Context, cfg *config.Config, logger *logging.Logger, limiter *ratelimit.Limiter, httpClient *http.Client, writer *output.Writer, exporter *oxg3n.Exporter, diffBaseline map[string]output.Record, diffRemaining map[string]output.Record, diffStats *diffSummary, watchKnown map[string]output.Record, notifier *webhook.Notifier, tracker *stats.Tracker, verboseEnabled bool) error {
	subdomainSources := make(map[string][]string)
	var subdomainSourcesMu sync.RWMutex
	zoneRecords := make(map[string]map[string][]string)
	totalDiscovered := 0

	if cfg.Mode == config.ModePassive || cfg.Mode == config.ModeAll {
		passiveSources, err := buildPassiveSources(cfg, httpClient)
		if err != nil {
			return err
		}

		resolveOpts := resolver.Options{
			Server:       cfg.DNSServer,
			Timeout:      cfg.DNSTimeout,
			RateLimiter:  limiter,
			CacheEnabled: cfg.DNSCache,
			CacheSize:    cfg.DNSCacheSize,
		}
		dnsResolver, err := resolver.New(resolveOpts)
		if err != nil {
			return fmt.Errorf("configuring resolver: %w", err)
		}

		hostnamesCh := make(chan string)
		resultsCh := dnsResolver.ResolveStream(ctx, hostnamesCh, cfg.Threads)

		passiveEvents, waitFn := passive.AggregateStream(ctx, cfg.Domain, passiveSources, passive.Options{Parallel: cfg.ParallelSources, SourceTimeout: 30 * time.Second})

		var passiveWG sync.WaitGroup
		passiveWG.Add(1)
		go func() {
			defer passiveWG.Done()
			defer close(hostnamesCh)

			seen := make(map[string]struct{})
			loggedErrors := make(map[string]struct{})

			for event := range passiveEvents {
				if event.Err != nil {
					source := event.Source
					if source == "" {
						source = "unknown"
					}
					if _, logged := loggedErrors[source]; !logged {
						logger.Warnf("Passive source %s error: %v", source, event.Err)
						loggedErrors[source] = struct{}{}
					}
					continue
				}

				subdomain := strings.TrimSpace(event.Subdomain)
				if subdomain == "" {
					continue
				}

				sourceName := strings.TrimSpace(event.Source)
				if sourceName == "" {
					sourceName = "unknown"
				}

				subdomain = strings.ToLower(subdomain)

				subdomainSourcesMu.Lock()
				addSource(subdomainSources, subdomain, sourceName)
				subdomainSourcesMu.Unlock()

				if _, exists := seen[subdomain]; !exists {
					seen[subdomain] = struct{}{}
					select {
					case <-ctx.Done():
						return
					case hostnamesCh <- subdomain:
					}
				}
			}

			summary := waitFn()
			for name, sourceErr := range summary.Errors {
				if name == "" || sourceErr == nil {
					continue
				}
				if _, logged := loggedErrors[name]; logged {
					continue
				}
				logger.Warnf("Passive source %s error: %v", name, sourceErr)
			}
		}()

		count, err := processResolutions(ctx, cfg, logger, writer, exporter, diffBaseline, diffRemaining, diffStats, watchKnown, notifier, tracker, verboseEnabled, subdomainSources, &subdomainSourcesMu, zoneRecords, dnsResolver, limiter, resultsCh)
		if err != nil {
			passiveWG.Wait()
			return err
		}

		totalDiscovered += count
		passiveWG.Wait()
	}

	if cfg.Mode == config.ModeActive || cfg.Mode == config.ModeAll {
		ztOpts := zonetransfer.Options{
			Domain:      cfg.Domain,
			DNSServer:   cfg.DNSServer,
			Timeout:     cfg.Timeout,
			Verbose:     verboseEnabled,
			LogWriter:   logger.Writer(logging.LevelDebug),
			RateLimiter: limiter,
		}

		transfers, err := zonetransfer.Run(ctx, ztOpts)
		if err != nil {
			return fmt.Errorf("active zone transfer: %w", err)
		}

		for _, transfer := range transfers {
			for hostname := range transfer.Records {
				subdomainSourcesMu.Lock()
				addSource(subdomainSources, hostname, "active:zonetransfer")
				subdomainSourcesMu.Unlock()
			}
			mergeZoneRecords(zoneRecords, transfer.Records)
		}

		progressWriter := logger.ConsoleWriter()

		opts := bruteforce.Options{
			Domain:             cfg.Domain,
			WordlistPath:       cfg.WordlistPath,
			Permutations:       cfg.Permutations,
			PermutationThreads: cfg.PermutationThreads,
			DNSServer:          cfg.DNSServer,
			Timeout:            cfg.DNSTimeout,
			Workers:            cfg.Threads,
			AutoTune:           cfg.AutoTune,
			ProgressWriter:     progressWriter,
			RateLimiter:        limiter,
		}

		results, err := bruteforce.Run(ctx, opts)
		if err != nil {
			return fmt.Errorf("active bruteforce: %w", err)
		}

		for _, res := range results {
			subdomainSourcesMu.Lock()
			addSource(subdomainSources, res.Subdomain, "active:bruteforce")
			subdomainSourcesMu.Unlock()
		}

		if len(subdomainSources) > 0 {
			subdomains := make([]string, 0, len(subdomainSources))
			for subdomain := range subdomainSources {
				subdomains = append(subdomains, subdomain)
			}
			sort.Strings(subdomains)

			resolveOpts := resolver.Options{
				Server:       cfg.DNSServer,
				Timeout:      cfg.DNSTimeout,
				RateLimiter:  limiter,
				CacheEnabled: cfg.DNSCache,
				CacheSize:    cfg.DNSCacheSize,
			}
			dnsResolver, err := resolver.New(resolveOpts)
			if err != nil {
				return fmt.Errorf("configuring resolver: %w", err)
			}

			resultsCh := dnsResolver.ResolveAll(ctx, subdomains, cfg.Threads)

			count, err := processResolutions(ctx, cfg, logger, writer, exporter, diffBaseline, diffRemaining, diffStats, watchKnown, notifier, tracker, verboseEnabled, subdomainSources, &subdomainSourcesMu, zoneRecords, dnsResolver, limiter, resultsCh)
			if err != nil {
				return err
			}
			totalDiscovered += count
		} else if totalDiscovered == 0 {
			logger.Infof("No subdomains discovered for %s", cfg.Domain)
		}
	} else if totalDiscovered == 0 {
		logger.Infof("No subdomains discovered for %s", cfg.Domain)
	}

	if exporter != nil {
		if err := flushExporter(ctx, cfg, logger, exporter); err != nil {
			return err
		}
	}

	if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
}

func processResolutions(ctx context.Context, cfg *config.Config, logger *logging.Logger, writer *output.Writer, exporter *oxg3n.Exporter, diffBaseline map[string]output.Record, diffRemaining map[string]output.Record, diffStats *diffSummary, watchKnown map[string]output.Record, notifier *webhook.Notifier, tracker *stats.Tracker, verboseEnabled bool, subdomainSources map[string][]string, subdomainSourcesMu *sync.RWMutex, zoneRecords map[string]map[string][]string, dnsResolver *resolver.Resolver, limiter *ratelimit.Limiter, resultsCh <-chan resolver.Result) (int, error) {
	if resultsCh == nil {
		return 0, nil
	}

	var wildcardProfile filters.WildcardProfile
	if cfg.FilterWildcards && dnsResolver != nil {
		profile, err := filters.DetectWildcard(ctx, dnsResolver, cfg.Domain, 3)
		if err != nil {
			if logger != nil {
				logger.Warnf("Wildcard detection error: %v", err)
			}
		} else {
			wildcardProfile = profile
			if wildcardProfile.Active() && logger != nil {
				logger.Infof("Wildcard DNS detected; matching resolutions will be filtered")
			}
		}
	}

	var probeClient *probe.Client
	if cfg.ProbeHTTP {
		probeClient = probe.NewClient(probe.Options{Timeout: cfg.Timeout, HTTPClient: netutil.NewHTTPClient(cfg.Timeout, limiter), ScreenshotDir: cfg.ScreenshotDir})
	}

	seenIPs := make(map[string]struct{})
	if !cfg.UniqueIPs {
		seenIPs = nil
	}

	total := 0

	for resolution := range resultsCh {
		subdomain := resolution.Subdomain
		if subdomain == "" {
			continue
		}

		subdomainSourcesMu.RLock()
		sources := append([]string(nil), subdomainSources[subdomain]...)
		subdomainSourcesMu.RUnlock()

		mergedIPs, mergedRecords := mergeResolution(resolution, zoneRecords[subdomain])
		resolved := len(mergedIPs) > 0 || len(mergedRecords) > 0
		if tracker != nil {
			tracker.RecordAttempt(resolved)
		}

		normalized := output.Record{}
		normalized.Subdomain = strings.ToLower(strings.TrimSpace(subdomain))

		if cfg.FilterWildcards && wildcardProfile.Active() && wildcardProfile.Matches(resolution) {
			if verboseEnabled && logger != nil {
				logger.Debugf("Skipping wildcard subdomain: %s", subdomain)
			}
			if diffRemaining != nil && normalized.Subdomain != "" {
				delete(diffRemaining, normalized.Subdomain)
			}
			continue
		}

		if !cfg.ShowAll && len(mergedIPs) == 0 && len(mergedRecords) == 0 {
			subdomainSourcesMu.Lock()
			delete(subdomainSources, subdomain)
			subdomainSourcesMu.Unlock()
			delete(zoneRecords, subdomain)
			if diffRemaining != nil && normalized.Subdomain != "" {
				delete(diffRemaining, normalized.Subdomain)
			}
			continue
		}

		if resolution.Err != nil && logger != nil {
			logger.Warnf("DNS resolution %s error: %v", subdomain, resolution.Err)
		}

		if cfg.FilterWildcards && filters.IsCDNResponse(mergedRecords) {
			if verboseEnabled && logger != nil {
				logger.Debugf("Skipping CDN-derived subdomain: %s", subdomain)
			}
			subdomainSourcesMu.Lock()
			delete(subdomainSources, subdomain)
			subdomainSourcesMu.Unlock()
			delete(zoneRecords, subdomain)
			if diffRemaining != nil && normalized.Subdomain != "" {
				delete(diffRemaining, normalized.Subdomain)
			}
			continue
		}

		if len(cfg.Scope) > 0 && !matchesScope(subdomain, cfg.Scope) {
			if verboseEnabled && logger != nil {
				logger.Debugf("Skipping subdomain outside scope: %s", subdomain)
			}
			subdomainSourcesMu.Lock()
			delete(subdomainSources, subdomain)
			subdomainSourcesMu.Unlock()
			delete(zoneRecords, subdomain)
			if diffRemaining != nil && normalized.Subdomain != "" {
				delete(diffRemaining, normalized.Subdomain)
			}
			continue
		}

		if cfg.UniqueIPs {
			mergedIPs, mergedRecords = filterUniqueIPs(mergedIPs, mergedRecords, seenIPs)
			if len(mergedIPs) == 0 {
				subdomainSourcesMu.Lock()
				delete(subdomainSources, subdomain)
				subdomainSourcesMu.Unlock()
				delete(zoneRecords, subdomain)
				if diffRemaining != nil && normalized.Subdomain != "" {
					delete(diffRemaining, normalized.Subdomain)
				}
				continue
			}
		}

		record := output.Record{
			Subdomain:   subdomain,
			Source:      strings.Join(sources, ","),
			IPAddresses: mergedIPs,
			DNSRecords:  mergedRecords,
		}
		if cfg.ProbeHTTP && probeClient != nil {
			record.HTTPServices = probeClient.Probe(ctx, subdomain)
		}
		if record.Timestamp == "" {
			record.Timestamp = time.Now().UTC().Format(time.RFC3339)
		}

		normalized = normalizeDiffRecord(record)

		if watchKnown != nil && normalized.Subdomain != "" {
			if prev, ok := watchKnown[normalized.Subdomain]; ok {
				if diffRecordsEqual(prev, normalized) {
					if diffRemaining != nil {
						delete(diffRemaining, normalized.Subdomain)
					}
					continue
				}
				record.Change = "updated"
			} else {
				record.Change = "new"
			}
		}

		if diffBaseline != nil {
			if normalized.Subdomain != "" {
				if prev, ok := diffBaseline[normalized.Subdomain]; ok {
					if !diffRecordsEqual(prev, normalized) {
						record.Change = "updated"
						if diffStats != nil {
							diffStats.updated++
						}
					}
					if diffRemaining != nil {
						delete(diffRemaining, normalized.Subdomain)
					}
				} else {
					if diffStats != nil {
						diffStats.added++
					}
					record.Change = "new"
				}
			}
		}

		if err := writer.WriteRecord(record); err != nil {
			return total, fmt.Errorf("writing record: %w", err)
		}
		total++

		if tracker != nil {
			tracker.RecordDiscovery(sources)
		}

		if exporter != nil {
			if err := exporter.AddRecord(ctx, record); err != nil {
				return total, fmt.Errorf("exporting to 0xg3n: %w", err)
			}
		}

		if notifier != nil {
			if err := notifier.Notify(ctx, cfg.Domain, record); err != nil {
				return total, fmt.Errorf("sending webhook notification: %w", err)
			}
		}

		if watchKnown != nil && normalized.Subdomain != "" {
			watchKnown[normalized.Subdomain] = normalized
		}
		if diffBaseline != nil && normalized.Subdomain != "" {
			diffBaseline[normalized.Subdomain] = normalized
		}

		subdomainSourcesMu.Lock()
		delete(subdomainSources, subdomain)
		subdomainSourcesMu.Unlock()
		delete(zoneRecords, subdomain)
	}

	return total, nil
}

func flushExporter(ctx context.Context, cfg *config.Config, logger *logging.Logger, exporter *oxg3n.Exporter) error {
	if exporter == nil {
		return nil
	}

	flushCtx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	summary, err := exporter.Flush(flushCtx)
	if err != nil {
		return fmt.Errorf("finalising 0xg3n export: %w", err)
	}

	if summary.TotalRecords > 0 || summary.BatchesSent > 0 {
		logger.Infof("0xg3n export complete: %d record(s) across %d batch(es)", summary.TotalRecords, summary.BatchesSent)
	} else {
		logger.Infof("0xg3n export complete: no records to send")
	}

	return nil
}

func cloneDiffBaseline(baseline map[string]output.Record) map[string]output.Record {
	if baseline == nil {
		return nil
	}
	copy := make(map[string]output.Record, len(baseline))
	for key, value := range baseline {
		copy[key] = value
	}
	return copy
}

func logScanSummary(logger *logging.Logger, cfg *config.Config, snapshot stats.Snapshot) {
	if logger == nil || cfg == nil {
		return
	}

	duration := snapshot.Duration
	durationStr := "<1s"
	if duration > 0 {
		rounded := duration.Truncate(time.Second)
		if rounded == 0 {
			rounded = duration
		}
		durationStr = rounded.String()
	}

	unresolved := snapshot.Attempts - snapshot.Resolved
	if unresolved < 0 {
		unresolved = 0
	}

	logger.Infof("Scan complete for %s: %d subdomains discovered (%d resolved, %d unresolved)", cfg.Domain, snapshot.TotalFound, snapshot.Resolved, unresolved)
	logger.Infof("Resolution attempts: %d total (success rate %.1f%%) across %s", snapshot.Attempts, snapshot.ResolutionRate(), durationStr)
	logger.Infof("Active/passive discovery ratio: %s", snapshot.ActivePassiveRatio())

	if breakdown := stats.FormatSourceBreakdown(snapshot.Sources, 5); breakdown != "" {
		logger.Infof("Top discovery sources: %s", breakdown)
	}

	if cfg.LiveOutput() {
		logger.Infof("Results streamed to stdout using %s format", cfg.Format)
	} else if cfg.OutputPath != "" {
		logger.Infof("Results saved to %s", cfg.OutputPath)
	}
}

func buildPassiveSources(cfg *config.Config, httpClient *http.Client) ([]passive.Source, error) {
	ctClient := certtransparency.NewClient(
		certtransparency.WithHTTPClient(httpClient),
		certtransparency.WithTimeout(cfg.Timeout),
	)
	htClient := hackertarget.NewClient(
		hackertarget.WithHTTPClient(httpClient),
		hackertarget.WithTimeout(cfg.Timeout),
	)
	tcClient := threatcrowd.NewClient(
		threatcrowd.WithHTTPClient(httpClient),
		threatcrowd.WithTimeout(cfg.Timeout),
	)
	vtClient := virustotal.NewClient(cfg.VirusTotalAPIKey,
		virustotal.WithHTTPClient(httpClient),
		virustotal.WithTimeout(cfg.Timeout),
	)

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

func startRateLimitMonitor(ctx context.Context, limiter *ratelimit.Limiter, logger *logging.Logger) {
	if limiter == nil || logger == nil {
		return
	}

	status := limiter.Status()
	if status.Rate <= 0 {
		return
	}

	logger.Infof("Rate limit configured: %.2f req/s (bucket capacity %.2f token(s))", status.Rate, status.Capacity)

	ticker := time.NewTicker(5 * time.Second)

	go func() {
		defer ticker.Stop()
		warned := false

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snapshot := limiter.Status()
				percentUsed := snapshot.Utilization * 100
				if percentUsed < 0 {
					percentUsed = 0
				}
				if percentUsed > 100 {
					percentUsed = 100
				}

				logger.Infof("Rate limit status: %.2f req/s | %.2f token(s) remaining (%.0f%% used, refill in %s)", snapshot.Rate, snapshot.Remaining, percentUsed, formatRefillDuration(snapshot.RefillIn))

				if snapshot.Capacity > 0 && snapshot.Remaining <= snapshot.Capacity*0.2 {
					if !warned {
						logger.Warnf("Approaching rate limit capacity: %.2f token(s) remaining (<=20%% of bucket)", snapshot.Remaining)
						warned = true
					}
				} else if warned && snapshot.Remaining > snapshot.Capacity*0.4 {
					warned = false
				}
			}
		}
	}()
}

func formatRefillDuration(d time.Duration) string {
	if d <= 0 {
		return "ready"
	}
	if d < time.Millisecond {
		return "<1ms"
	}
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
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

type diffSummary struct {
	added        int
	updated      int
	removed      []string
	removedCount int
}

func normalizeDiffRecord(rec output.Record) output.Record {
	normalized := output.Record{}
	normalized.Subdomain = strings.ToLower(strings.TrimSpace(rec.Subdomain))
	normalized.Source = normalizeSources(rec.Source)
	normalized.IPAddresses = dedupeSortedStrings(rec.IPAddresses)

	if len(rec.DNSRecords) > 0 {
		normalized.DNSRecords = make(map[string][]string, len(rec.DNSRecords))
		for recordType, values := range rec.DNSRecords {
			recordType = strings.ToUpper(strings.TrimSpace(recordType))
			normalized.DNSRecords[recordType] = dedupeSortedStrings(values)
		}
	}

	if len(rec.HTTPServices) > 0 {
		services := make([]output.HTTPService, 0, len(rec.HTTPServices))
		for _, svc := range rec.HTTPServices {
			normalizedService := output.HTTPService{
				URL:        strings.ToLower(strings.TrimSpace(svc.URL)),
				StatusCode: svc.StatusCode,
				Error:      strings.TrimSpace(svc.Error),
				Banner:     strings.TrimSpace(svc.Banner),
				Title:      strings.TrimSpace(svc.Title),
				Snippet:    strings.TrimSpace(svc.Snippet),
			}
			services = append(services, normalizedService)
		}
		sort.Slice(services, func(i, j int) bool {
			if services[i].URL == services[j].URL {
				return services[i].StatusCode < services[j].StatusCode
			}
			return services[i].URL < services[j].URL
		})
		normalized.HTTPServices = services
	}

	return normalized
}

func normalizeSources(source string) string {
	if strings.TrimSpace(source) == "" {
		return ""
	}
	parts := strings.Split(source, ",")
	normalized := dedupeSortedStrings(parts)
	return strings.Join(normalized, ",")
}

func diffRecordsEqual(a, b output.Record) bool {
	normalizedA := normalizeDiffRecord(a)
	normalizedB := normalizeDiffRecord(b)

	if normalizedA.Subdomain != normalizedB.Subdomain {
		return false
	}
	if normalizedA.Source != normalizedB.Source {
		return false
	}
	if !equalStringSlices(normalizedA.IPAddresses, normalizedB.IPAddresses) {
		return false
	}
	if len(normalizedA.DNSRecords) != len(normalizedB.DNSRecords) {
		return false
	}
	for recordType, values := range normalizedA.DNSRecords {
		other, ok := normalizedB.DNSRecords[recordType]
		if !ok || !equalStringSlices(values, other) {
			return false
		}
	}
	if len(normalizedA.HTTPServices) != len(normalizedB.HTTPServices) {
		return false
	}
	for i := range normalizedA.HTTPServices {
		if !httpServicesEqual(normalizedA.HTTPServices[i], normalizedB.HTTPServices[i]) {
			return false
		}
	}
	return true
}

func httpServicesEqual(a, b output.HTTPService) bool {
	return a.URL == b.URL &&
		a.StatusCode == b.StatusCode &&
		a.Error == b.Error &&
		a.Banner == b.Banner &&
		a.Title == b.Title &&
		a.Snippet == b.Snippet
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		if !strings.HasSuffix(err.Error(), "help requested") {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
