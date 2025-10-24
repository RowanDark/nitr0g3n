# nitr0g3n Examples

The following scenarios demonstrate typical nitr0g3n workflows. Commands can be
run directly once nitr0g3n is installed (see the [README](README.md)).

## Scanning with all modes and comparing results

Run discovery in `passive`, `active`, and `all` modes to understand the value of
each strategy. Saving the results as JSON makes it easy to diff the output and
identify hosts that appear in only one mode:

```bash
nitro --domain example.com --mode passive --format json --output results/passive.json
nitro --domain example.com --mode active  --format json --output results/active.json
nitro --domain example.com --mode all     --format json --output results/all.json

diff -u results/passive.json results/active.json > results/mode-diff.txt
```

## Using environment variables for API keys

Many data sources require API keys. nitr0g3n reads them from environment
variables so keys never have to be hard-coded in scripts. Export the values
before running a scan and keep them out of shell history by using `read -s`:

```bash
read -s NITR0G3N_VIRUSTOTAL_API_KEY
read -s NITR0G3N_SECURITYTRAILS_API_KEY
export NITR0G3N_VIRUSTOTAL_API_KEY NITR0G3N_SECURITYTRAILS_API_KEY

nitro --domain example.com --mode passive --sources virustotal,securitytrails
```

## Integrating with other tools via piping

nitr0g3n prints discoveries to stdout, which makes it easy to pipe the results
into other tooling. The example below probes each host with `httpx` and extracts
the titles of responsive services using `jq`:

```bash
nitro --domain example.com --mode all --format json \
  | jq -r '.[].host' \
  | httpx -title -status-code
```

To enrich the data with open ports, pipe the output into `nmap`:

```bash
nitro --domain example.com --mode all --format text \
  | nmap -iL - -Pn -sV -oN results/nmap.txt
```

## Real-world scanning scenarios

### Attack surface review before a release

Run a comprehensive scan of staging infrastructure, probe HTTP endpoints, and
export the results for a security review meeting:

```bash
export NITR0G3N_VIRUSTOTAL_API_KEY=vt_123456
nitro --domain staging.example.com \
      --mode all \
      --probe \
      --format csv \
      --output reports/staging-scan.csv
```

Share the generated CSV with the engineering and security teams so they can
validate that only expected hosts are exposed.

### Incident response triage

During an incident, quickly inventory DNS assets related to a suspicious
hostname. Write a timestamped JSON file and feed it into downstream analysis:

```bash
timestamp=$(date +"%Y%m%d-%H%M%S")
nitro --domain compromised.example.com \
      --mode passive \
      --sources virustotal,crtsh,securitytrails \
      --format json \
      --output incidents/${timestamp}-compromised.json
```

The captured snapshot can then be diffed against previous runs to track
propagation or unauthorized changes.
