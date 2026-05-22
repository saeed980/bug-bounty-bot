# Professional Recon Guide - Bug Bounty Hunter

## Phase 1: Scope & Target Definition

### Read Program Scope First
```bash
# Always check:
# 1. In-scope domains/IPs
# 2. Out-of-scope assets
# 3. Excluded vulnerability types
# 4. Special rules

# Save scope to file
echo "target.com" > scope.txt
echo "*.target.com" >> scope.txt
```

---

## Phase 2: Passive Recon (No Direct Contact)

### ASN & IP Range Discovery
```bash
# Find ASN number
curl -s "https://api.bgpview.io/search?query_term=Target+Company" | jq '.data.asns[].asn'
whois -h whois.radb.net -- '-i origin AS12345' | grep route

# Get all IP ranges from ASN
amass intel -asn 12345
nmap --script targets-asn --script-args targets-asn.asn=12345

# BGP tools
curl "https://api.bgpview.io/asn/12345/prefixes" | jq '.data.ipv4_prefixes[].prefix'

# Shodan ASN search
shodan search "asn:AS12345" --fields ip_str,port,hostnames
```

### WHOIS & Reverse WHOIS
```bash
# Basic WHOIS
whois target.com
whois 1.2.3.4

# Reverse WHOIS (find all domains by same registrant)
# Tools: ViewDNS, DomainTools, SecurityTrails
curl "https://viewdns.info/reversewhois/?q=admin@target.com"

# Find registrant email from WHOIS
whois target.com | grep -iE "(email|registrant|admin|tech)"

# amass reverse WHOIS
amass intel -whois -d target.com
```

### Certificate Transparency (crt.sh)
```bash
# Find all subdomains via SSL certs
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# With grep for clean output
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | \
  sort -u | \
  grep -v "^$" > crt_subs.txt

# Also check:
curl -s "https://crt.sh/?q=target.com&output=json" | jq -r '.[].name_value'
```

### Passive Subdomain Enumeration
```bash
# subfinder (best passive tool)
subfinder -d target.com -o subfinder_subs.txt -v
subfinder -d target.com -all -recursive -o subfinder_subs.txt

# amass passive
amass enum -passive -d target.com -o amass_subs.txt

# assetfinder
assetfinder --subs-only target.com > assetfinder_subs.txt

# findomain
findomain -t target.com -o

# chaos (ProjectDiscovery)
chaos -d target.com -o chaos_subs.txt -key YOUR_KEY

# Combine all results
cat *_subs.txt | sort -u > all_subs.txt
echo "Total unique subdomains: $(wc -l < all_subs.txt)"
```

### Shodan Recon
```bash
# Install
pip install shodan
shodan init YOUR_API_KEY

# Search by org
shodan search 'org:"Target Company"' --fields ip_str,port,hostnames,product

# Search by SSL cert
shodan search 'ssl:"target.com"' --fields ip_str,port,hostnames

# Find specific services
shodan search 'org:"Target" product:"Apache"'
shodan search 'org:"Target" http.title:"Dashboard"'
shodan search 'org:"Target" http.title:"Jenkins"'
shodan search 'org:"Target" http.title:"Grafana"'
shodan search 'org:"Target" http.title:"Kibana"'
shodan search 'org:"Target" port:8080'
shodan search 'org:"Target" port:8443'

# Domain specific
shodan search 'hostname:target.com' --fields ip_str,port,hostnames
shodan search 'ssl.cert.subject.cn:target.com'

# Download results
shodan download results 'org:"Target Company"'
shodan parse results.json.gz --fields ip_str,port,hostnames

# Shodan CLI one-liners
shodan host 1.2.3.4  # Info on specific IP
```

### Google Dorking
```bash
# Subdomains
site:*.target.com -www

# Sensitive files
site:target.com ext:php OR ext:asp OR ext:aspx OR ext:jsp
site:target.com ext:sql OR ext:db OR ext:log
site:target.com ext:env OR ext:config OR ext:xml
site:target.com ext:bak OR ext:backup OR ext:old

# Login pages
site:target.com inurl:login OR inurl:signin OR inurl:admin

# API endpoints
site:target.com inurl:api OR inurl:v1 OR inurl:v2

# Exposed files
site:target.com "index of /"
site:target.com intitle:"index of" "config"

# Errors & debug
site:target.com "Warning: mysql_" OR "SQL syntax"
site:target.com "Fatal error" OR "stack trace"

# Credentials (careful!)
site:target.com "password" filetype:log
site:target.com "api_key" OR "apikey" OR "secret_key"
```

### GitHub Recon
```bash
# Manual search on GitHub
# Search: org:target api_key
# Search: org:target password
# Search: org:target secret
# Search: "target.com" api_key
# Search: "target.com" password
# Search: "target.com" BEGIN RSA

# truffleHog
trufflehog github --org=target --only-verified
trufflehog github --repo=https://github.com/target/repo

# gitleaks
gitleaks detect --source=/path/to/cloned/repo -v

# gitrob
gitrob analyze target

# git-secrets
git-secrets --scan /path/to/cloned/repo

# Find deleted secrets in git history
git clone https://github.com/target/repo
cd repo
git log --all --full-history
git show COMMIT_HASH
trufflehog git file://. --only-verified
```

### Wayback Machine / Historical Data
```bash
# waybackurls
echo target.com | waybackurls > wayback_urls.txt

# gau (GetAllUrls) - best tool
gau target.com > gau_urls.txt
gau --threads 5 target.com | sort -u > gau_urls.txt

# katana (crawl + wayback)
katana -u https://target.com -jc -d 3 -o katana_urls.txt

# Extract JS files from wayback
cat gau_urls.txt | grep "\.js$" | sort -u > js_files.txt

# Extract parameters
cat gau_urls.txt | grep "?" | uro | sort -u > params_urls.txt

# Find old/deleted endpoints
cat gau_urls.txt | grep -iE "(admin|api|internal|backup|config)" | sort -u
```

### DMARC & Email Security
```bash
# Check DMARC
dig TXT _dmarc.target.com

# p=none   = monitor only (can spoof!)
# p=quarantine = goes to spam
# p=reject = fully protected

# Check SPF
dig TXT target.com | grep spf

# Check DKIM
dig TXT default._domainkey.target.com

# MX records
dig MX target.com

# No DMARC = email spoofing possible = report it!
```

### Cloud Asset Discovery
```bash
# cloud_enum - find all cloud assets
python3 cloud_enum.py -k target -k targetcompany -k target-prod

# S3 buckets
python3 cloud_enum.py -k target --disable-azure --disable-gcp

# Manual S3 checks
aws s3 ls s3://target --no-sign-request
aws s3 ls s3://target-prod --no-sign-request
aws s3 ls s3://target-backup --no-sign-request
aws s3 ls s3://target-dev --no-sign-request
aws s3 ls s3://target-staging --no-sign-request

# S3Scanner
python3 s3scanner.py --bucket target
python3 s3scanner.py --bucket-file buckets.txt

# GrayhatWarfare - online search
# https://buckets.grayhatwarfare.com/

# Azure blobs
curl https://target.blob.core.windows.net

# GCP buckets
curl https://storage.googleapis.com/target
```

---

## Phase 3: Active Recon

### DNS Enumeration
```bash
# Basic DNS records
dig A target.com
dig AAAA target.com
dig MX target.com
dig NS target.com
dig TXT target.com
dig ANY target.com

# Zone transfer attempt
dig axfr @ns1.target.com target.com
fierce --domain target.com

# Reverse DNS
dig -x 1.2.3.4
hakrevdns -d 1.2.3.0/24

# DNS brute force
puredns bruteforce /wordlists/dns_wordlist.txt target.com -r resolvers.txt -o dns_brute.txt

# dnsx - fast DNS toolkit
dnsx -l subdomains.txt -a -aaaa -cname -mx -txt -o dns_results.txt
```

### Active Subdomain Enumeration
```bash
# puredns (fast + accurate)
puredns bruteforce /wordlists/subdomains.txt target.com \
  -r /wordlists/resolvers.txt \
  -o active_subs.txt

# ffuf subdomain brute force
ffuf -u "https://FUZZ.target.com" \
  -w /wordlists/subdomains.txt \
  -mc 200,301,302,403 \
  -o ffuf_subs.json

# massdns
massdns -r resolvers.txt -t A -o S -w massdns_results.txt wordlist.txt

# Best wordlists for subdomain brute force
# https://wordlists.assetnote.io/ (best!)
# SecLists/Discovery/DNS/
```

### Subdomain Permutations & Alterations
```bash
# gotator
gotator -sub subdomains.txt -perm permutations.txt -depth 1 -numbers 3 -o permutations_out.txt

# altdns
altdns -i subdomains.txt -o altdns_out.txt -w /wordlists/words.txt

# dnsgen
cat subdomains.txt | dnsgen - | massdns -r resolvers.txt -t A -o S

# Common permutation patterns to try:
# dev-api, api-dev, api2, staging-api, new-api
# prod-api, test-api, beta-api, internal-api
# admin-portal, portal-admin, mgmt, management
```

### HTTP Probing
```bash
# httpx - probe all subdomains
cat all_subs.txt | httpx -silent -o alive_hosts.txt

# With more details
httpx -l all_subs.txt \
  -title \
  -status-code \
  -tech-detect \
  -content-length \
  -server \
  -o httpx_results.txt

# Full probe
httpx -l all_subs.txt \
  -silent \
  -title \
  -status-code \
  -tech-detect \
  -follow-redirects \
  -threads 50 \
  -o full_probe.txt

# Filter interesting results
cat httpx_results.txt | grep -v "404\|301 to https://target.com/"
```

### Screenshots
```bash
# gowitness
gowitness scan -f alive_hosts.txt --write-db
gowitness report generate

# aquatone
cat alive_hosts.txt | aquatone -out ./aquatone_results/

# eyewitness
python3 EyeWitness.py -f alive_hosts.txt --web -d ./eyewitness_results/

# View results
# Open gowitness/aquatone HTML report
# Look for: admin panels, login pages, default installs, interesting apps
```

### Port Scanning
```bash
# masscan - fast port discovery
masscan -p1-65535 1.2.3.0/24 --rate=1000 -oX masscan_results.xml

# nmap - detailed service scan
nmap -sV -sC -p- --open target.com -oN nmap_results.txt
nmap -sV -sC -p 80,443,8080,8443,8000,3000,4000,5000,9000 target.com

# naabu - fast port scanner
naabu -l alive_hosts.txt -p 80,443,8080,8443,8000,3000,9090,9200 -o ports.txt
naabu -host target.com -p - -o all_ports.txt

# Combine: find open ports then probe with httpx
naabu -l hosts.txt -p 80,443,8080,8443,8000,3000 | httpx -title -status-code
```

### Virtual Host (VHost) Scanning
```bash
# ffuf vhost scan
ffuf -u "https://target.com/" \
  -H "Host: FUZZ.target.com" \
  -w /wordlists/subdomains.txt \
  -mc 200,301,302 \
  -fs BASELINE_SIZE

# gobuster vhost
gobuster vhost -u https://target.com \
  -w /wordlists/subdomains.txt \
  --append-domain

# Find apps on same IP with different hostnames
curl -H "Host: internal.target.com" https://TARGET_IP/
curl -H "Host: admin.target.com" https://TARGET_IP/
```

---

## Phase 4: Content Discovery

### Directory & File Bruteforce
```bash
# ffuf - fastest
ffuf -u "https://target.com/FUZZ" \
  -w /wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  -mc 200,301,302,403 \
  -o dirs.json

# With extensions
ffuf -u "https://target.com/FUZZ" \
  -w /wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt \
  -e .php,.asp,.aspx,.jsp,.html,.txt,.bak,.old,.backup,.sql,.zip \
  -mc 200,301,302,403

# feroxbuster - recursive
feroxbuster -u https://target.com \
  -w /wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  -x php,asp,aspx,jsp \
  --depth 3 \
  -o ferox_results.txt

# dirsearch
python3 dirsearch.py -u https://target.com \
  -e php,asp,aspx,jsp,txt,bak \
  --output=dirsearch_results.txt

# gobuster
gobuster dir -u https://target.com \
  -w /wordlists/common.txt \
  -x php,txt,html \
  -o gobuster_results.txt
```

### Important Paths to Always Check
```bash
# Admin panels
/admin /administrator /admin.php /admin/login
/wp-admin /cpanel /phpmyadmin /adminer.php

# API docs
/swagger /swagger-ui /swagger.json /api-docs
/openapi.json /redoc /graphql /graphiql

# Sensitive files
/.env /config.php /configuration.php /config.yaml
/.git/HEAD /robots.txt /sitemap.xml /crossdomain.xml
/phpinfo.php /info.php /test.php /debug.php

# Backup files
/backup.zip /backup.tar.gz /db.sql /dump.sql
/config.php.bak /wp-config.php.bak

# Monitoring/Debug
/server-status /server-info /nginx_status /health
/metrics /actuator /actuator/env /actuator/health
/debug /console /trace /heapdump

# API versioning
/api/v1/ /api/v2/ /api/v3/ /api/beta/
/rest/v1/ /internal/ /private/
```

### Parameter Discovery
```bash
# arjun - best parameter finder
arjun -u https://target.com/api/endpoint -m GET
arjun -u https://target.com/api/endpoint -m POST
arjun -u https://target.com/api/endpoint -m GET -w /wordlists/params.txt

# paramspider
python3 paramspider.py -d target.com -o paramspider_results.txt

# x8 - parameter discovery
x8 -u "https://target.com/?" -w /wordlists/params.txt

# From wayback URLs (already have params)
cat gau_urls.txt | grep "?" | uro | sort -u > existing_params.txt

# qsreplace - test all params
cat existing_params.txt | qsreplace "FUZZ" | ffuf -u FUZZ -w payloads.txt
```

### JS File Analysis
```bash
# Download all JS files
cat gau_urls.txt | grep "\.js$" | sort -u > js_files.txt

# LinkFinder - extract endpoints from JS
python3 linkfinder.py -i https://target.com -d -o results.html

# For single JS file
python3 linkfinder.py -i https://target.com/app.js -o results.html

# SecretFinder - find secrets in JS
python3 SecretFinder.py -i https://target.com/app.js -o results.html

# Manual grep for secrets
curl -s https://target.com/app.js | grep -iE \
  "(api_key|apikey|secret|password|token|auth|aws|firebase|stripe|twilio)" 

# Extract all URLs from JS
curl -s https://target.com/app.js | \
  grep -oE '"(https?://[^"]+)"' | \
  tr -d '"' | sort -u

# Source maps (jackpot!)
curl -s https://target.com/app.js.map | python3 -m json.tool
# Contains original source code!
```

---

## Phase 5: Automation Pipeline

### Full Recon One-Liner
```bash
TARGET="target.com"

# Step 1: Subdomains
subfinder -d $TARGET -silent | \
  anew subs.txt

# Step 2: Check alive
cat subs.txt | httpx -silent | \
  anew alive.txt

# Step 3: Screenshot
gowitness scan -f alive.txt

# Step 4: CVE scan
nuclei -l alive.txt -t cves/ -t exposures/ -o nuclei_results.txt

# Step 5: Parameter URLs
echo $TARGET | gau | grep "?" | uro | anew params.txt
```

### Automated Recon Script
```bash
#!/bin/bash
TARGET=$1
OUT="recon_$TARGET"
mkdir -p $OUT

echo "[*] Starting recon for $TARGET"

# Subdomains
echo "[*] Gathering subdomains..."
subfinder -d $TARGET -o $OUT/subfinder.txt -silent
amass enum -passive -d $TARGET -o $OUT/amass.txt
assetfinder --subs-only $TARGET > $OUT/assetfinder.txt
curl -s "https://crt.sh/?q=%.$TARGET&output=json" | jq -r '.[].name_value' | sort -u > $OUT/crtsh.txt

# Combine
cat $OUT/*.txt | sort -u | grep -v "^$" > $OUT/all_subs.txt
echo "[+] Found $(wc -l < $OUT/all_subs.txt) subdomains"

# Probe alive
echo "[*] Probing alive hosts..."
httpx -l $OUT/all_subs.txt -silent -title -status-code -tech-detect -o $OUT/alive.txt
echo "[+] Alive: $(wc -l < $OUT/alive.txt)"

# Screenshots
echo "[*] Taking screenshots..."
gowitness scan -f $OUT/alive.txt

# Nuclei
echo "[*] Running nuclei..."
nuclei -l $OUT/alive.txt -t cves/ -t exposures/ -t misconfigurations/ \
  -o $OUT/nuclei.txt -silent

# URLs
echo "[*] Gathering URLs..."
echo $TARGET | gau --threads 5 > $OUT/gau_urls.txt
echo "[+] URLs: $(wc -l < $OUT/gau_urls.txt)"

# JS files
cat $OUT/gau_urls.txt | grep "\.js$" | sort -u > $OUT/js_files.txt

echo "[+] Recon complete! Results in $OUT/"
```

### Nuclei Templates - Full Scan
```bash
# All templates
nuclei -l alive.txt -t ~/nuclei-templates/ -o nuclei_all.txt

# Specific categories
nuclei -l alive.txt -t cves/ -severity critical,high -o cves.txt
nuclei -l alive.txt -t exposures/ -o exposures.txt
nuclei -l alive.txt -t misconfigurations/ -o misconfigs.txt
nuclei -l alive.txt -t takeovers/ -o takeovers.txt
nuclei -l alive.txt -t technologies/ -o tech.txt

# Exclude info
nuclei -l alive.txt -t ~/nuclei-templates/ \
  -severity critical,high,medium \
  -o nuclei_results.txt

# Fast scan
nuclei -l alive.txt -t cves/ -rate-limit 100 -bulk-size 50
```

---

## Phase 6: Prioritizing Targets

### Score Your Targets
```bash
# HIGH PRIORITY:
# - Admin panels / login pages
# - API endpoints
# - File upload features
# - New/beta subdomains
# - Payment/financial pages
# - OAuth/SSO integrations
# - Old/legacy subdomains (less security attention)

# MEDIUM PRIORITY:
# - Search functionality
# - User profiles
# - Export features
# - Settings pages

# LOW PRIORITY:
# - Static marketing pages
# - Blog/docs
# - Status pages

# Quick triage command
cat httpx_results.txt | \
  grep -iE "(admin|api|login|upload|payment|oauth|beta|dev|staging|internal)" | \
  sort > high_priority.txt
```

### Tech Stack Fingerprinting
```bash
# whatweb
whatweb https://target.com -v

# wappalyzer CLI
wappalyzer https://target.com

# Headers analysis
curl -I https://target.com | grep -iE "(server|x-powered-by|x-generator|x-aspnet)"

# Check common framework paths
# WordPress: /wp-login.php, /wp-json/
# Drupal: /user/login, /CHANGELOG.txt
# Joomla: /administrator/, /configuration.php
# Laravel: /login, /_debugbar/
# Django: /admin/, /api/
# Spring: /actuator/, /h2-console/
# Node: /package.json, /node_modules/
```

---

## Essential Tools Installation
```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/uro@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/sensepost/gowitness@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/pry0cc/axiom@latest

# Python tools
pip install shodan trufflehog gitleaks

# amass
go install github.com/owasp-amass/amass/v4/...@master

# Update nuclei templates
nuclei -update-templates
```

## Best Wordlists
```bash
# SecLists (essential)
git clone https://github.com/danielmiessler/SecLists

# Assetnote (best for API & subdomains)
# https://wordlists.assetnote.io/
wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2023_01_28.txt

# DNS resolvers
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
```
