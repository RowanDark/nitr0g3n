# nitr0g3n Examples

The following scenarios demonstrate typical nitr0g3n workflows. Commands can be
run directly once nitr0g3n is installed (see the [README](README.md)).

## Passive reconnaissance with VirusTotal

Query passive sources, enabling VirusTotal by providing an API key via
environment variable:

```bash
export NITR0G3N_VIRUSTOTAL_API_KEY=vt_123456
nitro --domain example.com --mode passive --sources virustotal,crtsh --format json
```

## Active bruteforce with permutations

Use a custom wordlist and enable permutations to cover numeric variants. Results
are written to a CSV file for further processing:

```bash
nitro --domain example.com \
      --mode active \
      --wordlist ./wordlists/top-1k.txt \
      --permutations \
      --format csv \
      --output results/example.csv
```

## Combined workflow with HTTP probing

Perform passive and active discovery, filter wildcard DNS, and probe HTTP/HTTPS
endpoints. Export discoveries to the 0xg3n hub while saving a local TXT report:

```bash
nitro --domain example.com \
      --mode all \
      --probe \
      --filter-wildcards \
      --export-0xgen https://hub.0xg3n.local/api/v1/import \
      --api-key $NITR0G3N_API_KEY \
      --format txt \
      --output reports/example.txt
```
