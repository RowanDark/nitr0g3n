# nitr0g3n

nitr0g3n is a reconnaissance toolkit focused on discovering subdomains and DNS
intelligence for a target domain. It combines passive data sources with active
DNS bruteforcing and exports the resulting intelligence to local files or the
0xg3n home hub.

## Installation

nitr0g3n requires Go 1.21 or later. Install from source with:

```bash
go install github.com/yourusername/nitr0g3n@latest
```

Alternatively clone the repository and build the binary:

```bash
git clone https://github.com/yourusername/nitr0g3n.git
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
      --export-0xgen https://hub.0xg3n.local/api/v1/import \
      --api-key $NITR0G3N_API_KEY
```

The exporter batches subdomains in groups of 100 and automatically retries on
recoverable HTTP errors. When `--export-0xgen` is omitted the integration is
skipped.

## Testing

Run the full unit test suite with:

```bash
go test ./...
```

A coverage report can be generated using `go test -cover ./...`.
