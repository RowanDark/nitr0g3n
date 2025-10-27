# nitr0g3n

nitr0g3n is a reconnaissance toolkit focused on discovering subdomains and DNS
intelligence for a target domain. It combines passive data sources with active
DNS bruteforcing and exports the resulting intelligence to local files or the
0xg3n home hub.

## Installation

nitr0g3n requires Go 1.21 or later.

### Install via go install
```bash
go install github.com/RowanDark/nitr0g3n@latest
```

### ⚠️ First Time Setup

After installation, you may need to add Go's bin directory to your PATH:
```bash
# Add Go bin to your PATH (choose based on your shell)
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc   # for bash
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc   # for zsh

# Reload your shell configuration
source ~/.bashrc  # or source ~/.zshrc
```

### Verify Installation
```bash
# Check if the binary is accessible
nitr0g3n --version

# If you see "command not found", the binary was installed but isn't in your PATH
# Find it with:
ls $(go env GOPATH)/bin/nitr0g3n

# Run directly if needed:
$(go env GOPATH)/bin/nitr0g3n --help
```

Run our installation checker:
```bash
curl -sSL https://raw.githubusercontent.com/RowanDark/nitr0g3n/main/scripts/check-install.sh | bash
```

Or manually:
```bash
nitr0g3n --version
```

### Alternative: Clone and Build
```bash
git clone https://github.com/RowanDark/nitr0g3n.git
cd nitr0g3n
go build -o nitro
sudo mv nitro /usr/local/bin/
```

### Creating the "nitro" Shortcut

If you prefer the shorter `nitro` command:
```bash
# Option 1: Symlink (recommended)
ln -s $(go env GOPATH)/bin/nitr0g3n $(go env GOPATH)/bin/nitro

# Option 2: Shell alias
echo 'alias nitro="nitr0g3n"' >> ~/.bashrc  # or ~/.zshrc
source ~/.bashrc
```

### Easy Installation with Make

If you've cloned the repository:
```bash
cd nitr0g3n

# Install to GOPATH/bin with helpful PATH instructions
make install

# Or install to /usr/local/bin (requires sudo)
make install-local

# Build locally
make build
./bin/nitr0g3n --help
```

## Usage

Run nitr0g3n with the target domain and desired enumeration mode:

```bash
nitro --domain example.com --mode all --format json --output results.json
```

Commonly used flags include:

| Flag | Description |
| --- | --- |
| `--domain` | Target domain to enumerate. |
| `--mode` | Enumeration mode: `passive`, `active`, or `all`. |
| `--format` | Output format: `json`, `csv`, or `txt`. |
| `--output` | Destination file path for results (defaults to stdout). |
| `--json-pretty` | Enable human-readable indentation when using JSON output. |
| `--diff` | Compare the current scan against a previous JSON results file. |
| `--watch` | Continuously rerun enumeration until interrupted. |
| `--watch-interval` | Interval between watch iterations (default: 5m). |
| `--threads` | Concurrent DNS worker count for active mode. |
| `--wordlist` | Custom wordlist path for bruteforce enumeration. |
| `--permutations` | Enable/disable wordlist permutations (default: enabled). |
| `--permutation-threads` | Number of threads to use when generating wordlist permutations (0 for automatic). |
| `--probe` | Probe discovered hosts over HTTP/HTTPS, capturing banners and screenshots. |
| `--screenshot-dir` | Directory to store generated probe screenshots. |
| `--filter-wildcards` | Filter DNS wildcard and CDN responses. |
| `--skip-wildcards` | Skip enumeration entirely when wildcard DNS responses are detected. |
| `--wildcard-batch` | Number of concurrent DNS queries used while detecting wildcard responses (default: 3). |
| `--export-0xgen` | 0xg3n hub endpoint to export findings. |
| `--api-key` | API key for authenticated exports and VirusTotal usage. |
| `--webhook` | Webhook endpoint that receives JSON notifications for each discovery. |
| `--webhook-secret` | Optional secret used to sign webhook payloads. |

You can also pipe newline-delimited targets into nitr0g3n. When `--domain` is
omitted, the CLI reads targets from standard input and processes them
sequentially, making it easy to integrate with other tools in a pipeline.

See `nitro --help` for the complete list of configuration options.

## Examples

* Passive enumeration only:

  ```bash
  nitro --domain example.com --mode passive
  ```

* Active bruteforce with a custom wordlist and TXT output:

  ```bash
  nitro --domain example.com --mode active --wordlist ./wordlist.txt --format txt --output results.txt
  ```

* Passive enumeration with VirusTotal and crt.sh, exporting live results to
  stdout:

  ```bash
  nitro --domain example.com --sources virustotal,crtsh --format json
  ```

* Monitor for new assets in real time with watch mode and webhook alerts:

  ```bash
  nitro --domain example.com --watch --watch-interval 10m \
       --webhook https://hooks.internal.local/nitr0g3n
  ```

* Chain nitr0g3n with other tooling by streaming targets via stdin:

  ```bash
  cat domains.txt | nitro --mode passive --format json
  ```

## 0xg3n Integration

nitr0g3n can export discovered assets to the 0xg3n home hub for centralised
tracking. Configure the exporter via:

```bash
nitro --domain example.com \
      --export-0xgen https://hub.your-0xg3n.com/api/v1/import \
      --api-key $NITR0G3N_API_KEY
```

The exporter batches subdomains in groups of 100 and automatically retries on
recoverable HTTP errors. Replace the host with your own deployed 0xg3n hub
endpoint; when `--export-0xgen` is omitted the integration is skipped.

## Performance Benchmarks

The following benchmarks were measured on a 16-core AMD Ryzen 7 5800X system
with 32 GB RAM and a 500 Mbps internet connection using Go 1.22.1. Real-world
performance depends on DNS resolver latency, passive source availability, and
wordlist quality, but these numbers provide a representative baseline.

### Typical Scan Durations

| Target domain size | Mode | Wordlist | Avg. duration | Notes |
| --- | --- | --- | --- | --- |
| ~100 known subdomains | `passive` | N/A | 18 s | Lightweight lookups against cached sources. |
| ~500 known subdomains | `all` | 50k words | 2 m 45 s | Balanced mix of passive + moderate bruteforce. |
| ~2k known subdomains | `all` | 200k words | 9 m 10 s | Includes HTTP probing of live hosts. |
| ~10k known subdomains | `active` | 1M words | 31 m | CPU-bound bruteforce; consider distributed runs. |

### Memory Usage Expectations

* Passive-only scans peak at ~250 MB RSS because results are streamed to disk
  as they arrive.
* Combined `all` mode with probing maintains a 450–600 MB RSS footprint thanks
  to internal batching of DNS and HTTP workers.
* Large active bruteforce jobs (≥1M words) may temporarily reach 1.2 GB RSS due
  to expanded wordlist queues; adjust `--threads` to trade speed for memory.

### Tooling Comparison

| Tool | Focus | Typical throughput | Notable strengths |
| --- | --- | --- | --- |
| nitr0g3n | Hybrid passive + active | 55–65 subdomains/s (active bruteforce) | Integrated 0xg3n export, adaptive rate limiting, wildcard filtering. |
| ffuf | HTTP fuzzing | 120–150 requests/s | Highly tunable HTTP engine for content discovery. |
| subfinder | Passive discovery | 80–100 subdomains/s | Broad passive source coverage with minimal setup. |
| amass | Comprehensive enumeration | 25–35 subdomains/s | Deep graph-based correlation and recursive brute forcing. |

Use nitr0g3n when you need a balanced reconnaissance workflow that blends
passive intelligence with curated bruteforce lists and can seamlessly push
findings into the 0xg3n hub. Pair it with ffuf for web content discovery or
subfinder for quick passive sweeps.

## Security Considerations

* **Respect rate limiting:** Many data sources and target domains enforce
  request throttling. Configure `--threads`, backoff intervals, and source
  selections to remain within published policies and avoid service disruption.
* **Authorized testing only:** Run nitr0g3n exclusively against assets you own
  or have explicit permission to assess. Unauthorized probing may violate laws
  or terms of service in your jurisdiction.
* **Practice responsible disclosure:** If you discover sensitive findings,
  follow coordinated disclosure guidelines. Notify the asset owner promptly,
  share only the necessary technical details, and allow a reasonable remediation
  window before publishing results.

## Error Handling

nitr0g3n attempts to detect and gracefully handle common issues that arise
during enumeration. The CLI surfaces actionable messages and, where possible,
offers hints on how to resolve the problem. Typical scenarios include:

* **Missing API credentials:** Passive sources such as VirusTotal require
  configured API keys before queries succeed. When nitr0g3n encounters a 401 or
  403 response, it skips the source and emits a warning that includes the name
  of the provider. Supply a valid key via `--api-key` or the corresponding
  environment variable before retrying the scan.
* **Rate limiting:** Remote APIs and DNS resolvers may throttle requests when
  limits are exceeded. nitr0g3n automatically backs off and retries with
  exponential delays, and records the behaviour in the log output. Reduce
  `--threads`, remove optional sources, or increase the delay between requests
  to avoid repeated throttling.
* **DNS resolution failures:** When active bruteforcing encounters SERVFAIL or
  NXDOMAIN responses, the tool classifies them as expected negative results and
  continues. Persistent lookup errors across all nameservers trigger a warning
  that suggests switching to a different resolver via `--resolver` or the
  configuration file.
* **File system write errors:** nitr0g3n writes results, probe screenshots, and
  diff snapshots to disk. If the destination directory is missing or has
  restricted permissions the CLI halts the affected export and reports the path
  that failed. Create the directory ahead of time or adjust permissions before
  rerunning.
* **Webhook delivery issues:** Failed HTTP callbacks are retried with a limited
  backoff schedule. After the retry budget is exhausted, nitr0g3n logs the final
  HTTP status code. Verify network reachability, TLS settings, and any required
  authentication headers when troubleshooting webhook integrations.

## Troubleshooting

When scans do not behave as expected, start with the following checks:

1. **Inspect the logs:** Run nitr0g3n with `--log-level debug` to view detailed
   diagnostic messages, including HTTP response codes, retry attempts, and
   resolver statistics.
2. **Validate configuration files:** Use `nitro --config path/to/config.yaml --dry-run`
   to verify that all sections parse correctly and that referenced files exist.
3. **Test connectivity:** Confirm outbound DNS and HTTPS connectivity from the
   running environment. Utilities like `dig`, `nslookup`, or `curl` can help
   pinpoint blocked ports and firewall restrictions.
4. **Simplify the workload:** Temporarily disable optional features such as
   probing, permutations, or exports to isolate the component that is failing.
5. **Review upstream status pages:** Many passive data sources publish service
   outage information. A sudden spike in errors may be due to provider downtime
   rather than local misconfiguration.

If issues persist, open a GitHub issue with a copy of the debug log (redacting
any sensitive data) and a description of the environment in which nitr0g3n is
running. Community members and maintainers can offer additional guidance based
on the collected diagnostics.

## Testing

Run the full unit test suite with:

```bash
go test ./...
```

A coverage report can be generated using `go test -cover ./...`.
