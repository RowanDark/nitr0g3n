# nitr0g3n

nitr0g3n is a reconnaissance toolkit focused on discovering subdomains and DNS
intelligence for a target domain. It combines passive data sources with active
DNS bruteforcing and exports the resulting intelligence to local files or the
0xg3n home hub.

## Installation

nitr0g3n requires Go 1.21 or later. Install from source with:

```bash
go install github.com/RowanDark/nitr0g3n@latest
```

Alternatively clone the repository and build the binary:

```bash
git clone https://github.com/RowanDark/nitr0g3n.git
cd nitr0g3n
go build ./...
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
| `--threads` | Concurrent DNS worker count for active mode. |
| `--wordlist` | Custom wordlist path for bruteforce enumeration. |
| `--permutations` | Enable/disable wordlist permutations (default: enabled). |
| `--probe` | Probe discovered hosts over HTTP/HTTPS. |
| `--filter-wildcards` | Filter DNS wildcard and CDN responses. |
| `--export-0xgen` | 0xg3n hub endpoint to export findings. |
| `--api-key` | API key for authenticated exports and VirusTotal usage. |

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

## Testing

Run the full unit test suite with:

```bash
go test ./...
```

A coverage report can be generated using `go test -cover ./...`.
