# Reconnaissance - Bug Bounty Hunter Guide

## ASN & Infrastructure Discovery
- Find ASN numbers → map entire IP ranges of target
- Tools: `amass`, `bgp.he.net`, `shodan.io`
- Command: `amass intel -asn <ASN_NUMBER>`
- Discover all IPs owned by company → find forgotten assets

## Microsoft / Cloud Interrogation
- Check Azure, O365, Teams exposure
- Tools: `AADInternals`, `o365recon`
- Find subdomains via: `*.onmicrosoft.com`

## Tracking Data & Analytics
- Google Analytics ID reuse across domains → find hidden assets
- Ad networks: same pixel ID = same company
- Tools: BuiltWith, SpyOnWeb, DNSlytics

## Shodan Recon
- Search: `org:"Target Company"` → exposed services
- Search: `ssl:"target.com"` → find all SSL certs
- Search: `http.title:"Dashboard" org:"Target"`
- Look for: Jenkins, Jira, Grafana, Kibana exposed

## Acquisitions
- Research company acquisitions → old domains still in scope
- Check: Crunchbase, LinkedIn, SEC filings
- Acquired companies = less security attention = more bugs

## Cloud Recon
- AWS: `target.s3.amazonaws.com` → check public buckets
- GCP: `storage.googleapis.com/target`
- Azure Blob: `target.blob.core.windows.net`
- Tools: `cloud_enum`, `S3Scanner`, `GrayhatWarfare`

## Reverse WHOIS
- Find all domains registered by same email/org
- Tools: ViewDNS.info, DomainTools, WhoisXML API
- `whois` data → pivot on registrant email → find hidden assets

## Reverse DNS & IP
- PTR records → find all hostnames on same IP
- Tools: `hakrevdns`, SecurityTrails, Shodan
- Same IP = same server = potentially same vuln

## DMARC Analysis
- No DMARC = email spoofing possible
- Check: `dig TXT _dmarc.target.com`
- `p=none` = monitoring only (can spoof)
- `p=reject` = fully protected

## Subdomain Enumeration
### Passive (no noise)
- `subfinder -d target.com`
- `amass enum -passive -d target.com`
- `assetfinder target.com`
- crt.sh: `https://crt.sh/?q=%.target.com`
- SecurityTrails, VirusTotal, Shodan

### Active (brute force)
- `ffuf -w wordlist.txt -u https://FUZZ.target.com`
- `puredns bruteforce wordlist.txt target.com`
- Best wordlists: Assetnote, SecLists

### Permutations & Alterations
- `altdns -i subdomains.txt -o output.txt`
- `gotator -sub subdomains.txt -perm permutations.txt`
- Patterns: `dev-api`, `api2`, `staging-api`, `new-admin`

## VHost Scanning
- Find virtual hosts on same IP
- `ffuf -w wordlist.txt -H "Host: FUZZ.target.com" -u http://IP`
- Many hidden apps share same IP

## GitHub Enumeration
- Search: `org:target api_key`
- Search: `org:target password`
- Search: `org:target secret`
- Tools: `trufflehog`, `gitleaks`, `gitrob`
- Check commit history! Secrets get committed and "deleted" but stay in history

## Screenshotting
- `gowitness scan -f subdomains.txt`
- `aquatone -list subdomains.txt`
- Visual recon → quickly identify interesting targets
- Look for: login pages, admin panels, error pages, default installs

## Prioritizing Recon Data
- Score targets: age of subdomain + tech stack + functionality
- Prioritize: newer subdomains, APIs, admin panels
- De-prioritize: static/marketing pages
