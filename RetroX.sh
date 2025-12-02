#!/usr/bin/env bash
# RetroX.sh - Advanced Complete Recon & Web App Testing Pipeline with Telegram Notifications
# Fixed: DNS, nmap, FFUF, Arjun, no crashes, full coverage
# Usage: ./RetroX.sh [domain] [output_dir] [telegram_bot_token] [telegram_chat_id]
# WARNING: Run only on authorized assets

set -euo pipefail
IFS=$'\n\t'

# ==================== CONFIGURATION ====================
TARGET_DOMAIN="${1:-}"
BASE_OUTDIR="${2:-retrox_output}"
TELEGRAM_BOT_TOKEN="${3:-123456789:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
TELEGRAM_CHAT_ID="${4:-123456789}"

# Interactive mode
if [[ -z "$TARGET_DOMAIN" ]]; then
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "RetroX.sh - Advanced Recon & Web Testing"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  read -p "Enter target domain (e.g., example.com): " TARGET_DOMAIN
  TARGET_DOMAIN=$(echo "$TARGET_DOMAIN" | xargs | sed 's|https\?://||; s|/.*||')
  [[ -z "$TARGET_DOMAIN" ]] && { echo "No domain. Exiting."; exit 1; }
  read -p "Enter output directory [retrox_output]: " user_outdir
  [[ -n "$user_outdir" ]] && BASE_OUTDIR="$user_outdir"
fi

# Telegram
send_telegram_message() {
  curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
    -d chat_id="$TELEGRAM_CHAT_ID" -d text="$1" -d parse_mode="Markdown" > /dev/null
}
send_telegram_message "RetroX Recon Started at $(date) for domain: $TARGET_DOMAIN"

# Performance
THREADS=${THREADS:-40}
DIG_PARALLEL=${DIG_PARALLEL:-20}
NUCLEI_THREADS=${NUCLEI_THREADS:-10}
NUCLEI_RATE_LIMIT=${NUCLEI_RATE_LIMIT:-30}
FFUF_CONCURRENCY=${FFUF_CONCURRENCY:-1}
FFUF_THREADS=${FFUF_THREADS:-10}
FFUF_RATE_LIMIT=${FFUF_RATE_LIMIT:-30}
ARJUN_CONCURRENCY=${ARJUN_CONCURRENCY:-2}
ARJUN_THREADS=${ARJUN_THREADS:-5}


# Paths
NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES:-/root/nuclei-templates}"
FFUF_WORDLIST="${FFUF_WORDLIST:-/root/SecLists/Discovery/Web-Content/raft-medium-directories.txt}"
FFUF_EXT="${FFUF_EXT:-php,html,js,txt,json,xml,asp,aspx,jsp,bak,old,zip,tar,gz}"
FFUF_HEADER_WORDLIST="${FFUF_HEADER_WORDLIST:-/root/SecLists/Discovery/Web-Content/burp-parameter-names.txt}"

# Flags
SKIP_FFUF=${SKIP_FFUF:-0}
SKIP_NUCLEI=${SKIP_NUCLEI:-0}
SKIP_NMAP=${SKIP_NMAP:-0}
SKIP_SCREENSHOTS=${SKIP_SCREENSHOTS:-0}
SKIP_ARJUN=${SKIP_ARJUN:-0}
DEEP_SCAN=${DEEP_SCAN:-0}

# ==================== VALIDATION ====================
REQUIRED=(amass assetfinder subfinder curl jq dnsx httpx waybackurls gau nuclei dig)
[[ "$SKIP_FFUF" -eq 0 ]] && REQUIRED+=(ffuf)
[[ "$SKIP_NMAP" -eq 0 ]] && REQUIRED+=(nmap)
[[ "$SKIP_SCREENSHOTS" -eq 0 ]] && REQUIRED+=(gowitness)
[[ "$SKIP_ARJUN" -eq 0 ]] && REQUIRED+=(arjun)

MISSING=()
for c in "${REQUIRED[@]}"; do
  ! command -v "$c" >/dev/null 2>&1 && MISSING+=("$c")
done

if (( ${#MISSING[@]} )); then
  echo "Missing required tools: ${MISSING[*]}"
  send_telegram_message "RetroX Error: Missing tools: ${MISSING[*]}"
  exit 2
fi

mkdir -p "$BASE_OUTDIR"
sanitize() { echo "$1" | sed 's/[^A-Za-z0-9._-]/_/g'; }

# ==================== SEMAPHORE ====================
FIFO_SEM="/tmp/retrox_sem.$$"
sem_init() { mkfifo "$FIFO_SEM"; exec 9<>"$FIFO_SEM"; rm -f "$FIFO_SEM"; for ((i=0;i<$1;i++)); do echo >&9; done; }
sem_wait() { read -u 9 -t 3600 || true; }
sem_post() { echo >&9 || true; }
sem_destroy() { exec 9>&- 2>/dev/null || true; }

trap 'cd "$PWD" 2>/dev/null; sem_destroy 2>/dev/null' EXIT

# ==================== SETUP ====================
domain="$TARGET_DOMAIN"
SDIR=$(sanitize "$domain")
OUT="$BASE_OUTDIR/$SDIR"
mkdir -p "$OUT"
cd "$OUT"

# ==================== PHASE 1: SUBDOMAIN ENUMERATION ====================
echo "[1/12] Subdomain enumeration..."
send_telegram_message "Starting *Subdomain Enumeration*..."

(amass enum -passive -d "$domain" -norecursive -o amass.tmp 2>/dev/null || true) &
(assetfinder --subs-only "$domain" > assetfinder.tmp 2>/dev/null || true) &
(subfinder -d "$domain" -silent -all -o subfinder.tmp 2>/dev/null || true) &
(curl -s "https://crt.sh/?q=%25${domain//./%2E}%25&output=json" | jq -r '.[]|.name_value,.common_name' 2>/dev/null | tr ',' '\n' | sed 's/^\*\.//g' | grep -E "\.${domain}$" | sort -u > crtsh.tmp || true) &
(curl -s "https://dns.bufferover.run/dns?q=.${domain}" | jq -r '.FDNS_A[],.RDNS[]' 2>/dev/null | cut -d',' -f2 | grep -E "\.${domain}$" > bufferover.tmp || true) &
(curl -s "https://api.hackertarget.com/hostsearch/?q=${domain}" | awk '{print $1}' | grep -E "\.${domain}$" > hackertarget.tmp || true) &
wait

cat amass.tmp assetfinder.tmp subfinder*.tmp crtsh.tmp bufferover.tmp hackertarget.tmp 2>/dev/null | sed 's/^\*\.//g; /^$/d' | sort -u > all_subs.txt
echo "   Found $(wc -l < all_subs.txt) subdomains"
send_telegram_message "*Subdomain Enumeration* completed. Found $(wc -l < all_subs.txt) subdomains."




# ==================== PHASE 2: DNS RESOLUTION (NEVER QUITS) ====================
echo "[2/12] DNS resolution with safe fallbacks..."
send_telegram_message "Starting *DNS Resolution*..."

# === CLEAN START ===
> resolved.txt.tmp
> dnsx_raw.txt

# === STEP 1: dnsx ===
dnsx -silent -a -resp -retry 3 -threads 50 -l all_subs.txt -o dnsx_raw.txt 2>/dev/null || true

grep -E ' A ' dnsx_raw.txt | \
  awk '{print $1 " " $3}' | \
  grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' > resolved.txt.tmp || true

# === STEP 2: dig fallback ===
< all_subs.txt grep -vf <(awk '{print $1}' resolved.txt.tmp 2>/dev/null || echo "") > unresolved.txt 2>/dev/null || true

if [[ -s unresolved.txt ]]; then
  echo "   Falling back to dig + 8.8.8.8 for $(wc -l < unresolved.txt) subdomains..."
  < unresolved.txt xargs -n1 -P20 bash -c '
    sub="$0"
    ip=$(dig +short A "$sub" @8.8.8.8 +timeout=5 2>/dev/null | grep -E "^[0-9]+\.[0-9]+" | head -1)
    [[ -n "$ip" ]] && echo "$sub $ip"
  ' > dig_fallback.txt 2>/dev/null || true
  cat dig_fallback.txt >> resolved.txt.tmp 2>/dev/null || true
  rm -f dig_fallback.txt
fi

# === STEP 3: Cloudflare fallback ===
< all_subs.txt grep -vf <(awk '{print $1}' resolved.txt.tmp 2>/dev/null || echo "") > unresolved2.txt 2>/dev/null || true
if [[ -s unresolved2.txt ]]; then
  < unresolved2.txt xargs -n1 -P20 bash -c '
    sub="$0"
    ip=$(dig +short A "$sub" @1.1.1.1 +timeout=5 2>/dev/null | grep -E "^[0-9]+\.[0-9]+" | head -1)
    [[ -n "$ip" ]] && echo "$sub $ip"
  ' > cf_fallback.txt 2>/dev/null || true
  cat cf_fallback.txt >> resolved.txt.tmp 2>/dev/null || true
  rm -f cf_fallback.txt
fi

# === STEP 4: Final cleanup ===
sort -u resolved.txt.tmp -o resolved.txt 2>/dev/null || > resolved.txt
awk '{print $2}' resolved.txt 2>/dev/null | sort -u > ips.txt

# === STEP 5: CNAMEs (SAFE) ===
< all_subs.txt xargs -n1 -P30 bash -c '
  c=$(dig +short CNAME "$0" @8.8.8.8 +timeout=5 2>/dev/null | head -1 | sed "s/\.$//")
  [[ -n "$c" ]] && echo -e "$0\t$c"
' > cnames.txt 2>/dev/null || > cnames.txt

awk '{print $2}' cnames.txt 2>/dev/null | sort -u > all_cnames.txt

# === STEP 6: Dangling ===
grep -Ei 'amazonaws|azure|heroku|github\.io|fastly|cloudapp|pages\.dev|vercel|s3\.|zendesk|shopify|tumblr|wordpress|ghost|readme\.io|bitbucket\.io|surge\.sh|helpjuice|helpscout|cargo\.site|statuspage\.io|uservoice|pantheon\.io|kinsta|acquia|agile\.crm|campaignmonitor|canny\.io|feedpress|freshdesk|getresponse|helprace|intercom|jazzhr|kajabi|kayako|mashery|mailgun|ngrok|proposify|sendgrid|simplebooklet|smartjob|smugmug|strikingly|surveygizmo|tave|teamwork|thinkific|tictail|tilda|unbounce|uberflip|webflow|wufoo|wishpond' \
  cnames.txt > dangling.txt 2>/dev/null || > dangling.txt

# === STEP 7: Stats ===
resolved_count=$(wc -l < resolved.txt 2>/dev/null || echo 0)
ip_count=$(wc -l < ips.txt 2>/dev/null || echo 0)
cname_count=$(wc -l < cnames.txt 2>/dev/null || echo 0)
dangling_count=$(wc -l < dangling.txt 2>/dev/null || echo 0)

echo "   Resolved: $resolved_count | IPs: $ip_count | CNAMEs: $cname_count | Dangling: $dangling_count"
send_telegram_message "*DNS Resolution* completed.\nResolved $resolved_count → $ip_count IPs."

# === CLEANUP ===
rm -f resolved.txt.tmp dnsx_raw.txt unresolved.txt unresolved2.txt




# ==================== PHASE 3: PORT SCANNING (CLEANED) ====================
if [[ "$SKIP_NMAP" -eq 0 && -s resolved.txt ]]; then
  echo "[3/12] Port scanning ALL valid subdomain IPs..."
  send_telegram_message "Starting *Port Scanning*..."

  > all_sub_ips.txt
  while IFS= read -r line; do
    ip=$(echo "$line" | awk '{print $2}')
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "$ip" >> all_sub_ips.txt
  done < resolved.txt

  total_valid=$(wc -l < all_sub_ips.txt)
  if [[ $total_valid -eq 0 ]]; then
    echo "   No valid IPs. Skipping."
    > open_ports.txt
    send_telegram_message "*Port Scanning* skipped."
  else
    echo "   Scanning $total_valid IPs..."
    ports=""; [[ "$DEEP_SCAN" -eq 1 ]] && ports="-p 1-65535"

    nmap -sT -Pn $ports -iL all_sub_ips.txt --open -T4 --host-timeout 5m --max-retries 2 \
      --min-rtt-timeout 100ms --max-rtt-timeout 2s --max-scan-delay 100ms \
      -oA nmap_ports_clean 2>&1 | tee nmap_ports_clean.log

    grep -E '^[0-9]+/(tcp|udp).*open' nmap_ports_clean.nmap 2>/dev/null | awk '{print $1}' | sed 's|/[a-z]*||' | sort -u > open_ports.txt
    echo "   Open ports: $(wc -l < open_ports.txt)"
    send_telegram_message "*Port Scanning* completed. Found $(wc -l < open_ports.txt) open ports."
  fi
else
  echo "[3/12] Nmap skipped"
  send_telegram_message "*Port Scanning* skipped."
fi




# ==================== PHASE 4: SERVICE DETECTION ====================
if [[ "$SKIP_NMAP" -eq 0 && -s open_ports.txt ]]; then
  echo "🔬 [4/12] Service detection with nmap..."
  send_telegram_message "🔍 Starting *Service Detection*..."
  
  # Extract top 20 IPs with most open ports
  awk -F: '{print $1}' open_ports.txt | sort | uniq -c | sort -rn | head -20 | awk '{print $2}' > top_ips.tmp
  
  if [[ -s top_ips.tmp ]]; then
    nmap -iL top_ips.tmp -sV -T4 --open -oA nmap_services --max-retries 1 --max-rtt-timeout 500ms \
      --max-scan-delay 20ms -Pn >/dev/null 2>&1 || true
    [[ -f nmap_services.xml ]] && echo "   ✓ Service scan complete: nmap_services.xml"
  fi
  send_telegram_message "✅ *Service Detection* completed."
else
  echo "⏭️  [4/12] Service detection skipped"
  send_telegram_message "⏭️ *Service Detection* skipped."
fi

# ==================== PHASE 5: URL COLLECTION (ALL SUBDOMAINS) ====================
echo "🕷️  [5/12] URL crawling for ALL subdomains (wayback + gau + katana)..."
send_telegram_message "🔍 Starting *URL Crawling*..."

# Wayback + GAU
<all_subs.txt xargs -P 20 -I{} bash -c \
  'waybackurls "{}" 2>/dev/null | sed "s/#.*//"; echo "{}" | gau --subs 2>/dev/null' | \
  sort -u > urls_archive.txt || true

# Active crawling with katana if available
if command -v katana >/dev/null 2>&1 && [[ -s all_subs.txt ]]; then
  katana -list all_subs.txt -silent -d 3 -jc -kf all -aff -o urls_katana.txt 2>/dev/null || true
  cat urls_archive.txt urls_katana.txt 2>/dev/null | sort -u > all_urls.txt
else
  cp urls_archive.txt all_urls.txt 2>/dev/null || >all_urls.txt
fi

echo "   ✓ Collected $(wc -l < all_urls.txt) URLs from all subdomains"
send_telegram_message "✅ *URL Crawling* completed. Collected $(wc -l < all_urls.txt) URLs."

# === PHASE 6: HTTP PROBING ===
echo "HTTP probing ALL subdomains with httpx (with scheme)..."
send_telegram_message "Starting *HTTP Probing*..."

# Add scheme safely
mkdir -p "$OUT"
< "$OUT/all_subs.txt" sed 's/^/https:\/\//' > "$OUT/subs_with_scheme.txt" 2>/dev/null || true

# Probe with httpx (fail gracefully)
if command -v httpx >/dev/null 2>&1; then
    httpx -list "$OUT/subs_with_scheme.txt" -silent -threads "$THREADS" -no-color -json \
      -timeout 10 -status-code -title -tech-detect -ip -follow-redirects \
      -o "$OUT/httpx_subs.json" 2>/dev/null || true

    # Extract alive hosts
    jq -r 'select(.url) | .url' "$OUT/httpx_subs.json" 2>/dev/null | sort -u > "$OUT/alive_hosts.txt" || true
else
    echo "httpx not found. Skipping HTTP probing."
    send_telegram_message "httpx not installed. Skipping HTTP probing."
    > "$OUT/alive_hosts.txt"
fi

# Probe crawled URLs too
if [[ -s "$OUT/all_urls.txt" ]]; then
    <"$OUT/all_urls.txt" httpx -silent -threads "$THREADS" -no-color -json -timeout 10 \
      -status-code -title -tech-detect -ip -follow-redirects \
      -o "$OUT/httpx_urls.json" 2>/dev/null || true

    jq -r 'select(.url) | .url' "$OUT/httpx_urls.json" 2>/dev/null | sort -u >> "$OUT/alive_hosts.txt" || true
fi

sort -u "$OUT/alive_hosts.txt" -o "$OUT/alive_hosts.txt"

# Technologies
jq -r 'select(.technologies) | .url + " => " + (.technologies | join(", "))' \
  "$OUT/httpx_subs.json" "$OUT/httpx_urls.json" 2>/dev/null | sort -u > "$OUT/technologies.txt" || true

echo "   Alive hosts: $(wc -l < "$OUT/alive_hosts.txt") | Technologies: $(wc -l < "$OUT/technologies.txt")"
send_telegram_message "HTTP Probing completed. Found $(wc -l < "$OUT/alive_hosts.txt") alive hosts."

# ==================== PHASE 7: SCREENSHOTS ====================
if [[ "$SKIP_SCREENSHOTS" -eq 0 && -s alive_hosts.txt ]]; then
  echo "📸 [7/12] Taking screenshots with gowitness..."
  send_telegram_message "🔍 Starting *Screenshots*..."
  mkdir -p screenshots
  gowitness file -f alive_hosts.txt --screenshot-path screenshots --disable-logging >/dev/null 2>&1 || true
  echo "   ✓ Screenshots saved: screenshots/"
  send_telegram_message "✅ *Screenshots* completed."
else
  echo "⏭️  [7/12] Screenshots skipped"
  send_telegram_message "⏭️ *Screenshots* skipped."
fi



# ==================== PHASE 8: PARAMETER EXTRACTION ====================
echo "🔑 [8/12] Parameter extraction and analysis..."
send_telegram_message "Starting *Parameter Extraction*..."

# ---- Extract plain parameter names ----
grep '?' all_urls.txt 2>/dev/null | \
  sed -n 's/.*?\([^#]*\).*/\1/p' | tr '&' '\n' | sed 's/=.*//' | \
  sort -u > params.txt || > params.txt

# ---- Build detailed param → value → URL map ----
> params_detailed.txt
grep '?' all_urls.txt 2>/dev/null > urls_with_qs.tmp || > urls_with_qs.tmp

while IFS= read -r url; do
  qs=$(echo "$url" | sed -n 's/^[^?]*?\(.*\)$/\1/p' | sed 's/#.*$//')
  [[ -z "$qs" ]] && continue

  # Write each param=value pair to a temp file for the inner loop
  echo "$qs" | tr '&' '\n' > param_pairs.tmp
  while IFS= read -r pair; do
    name=$(echo "$pair" | sed 's/=.*//')
    value=$(echo "$pair" | sed 's/[^=]*=//')
    [[ -n "$name" ]] && printf '%s\t%s\t%s\n' "$name" "$value" "$url"
  done < param_pairs.tmp
done < urls_with_qs.tmp >> params_detailed.txt

sort -u params_detailed.txt -o params_detailed.txt
rm -f urls_with_qs.tmp param_pairs.tmp

# ---- API / JSON endpoints ----
grep -iE '\.json|/api/|/v[0-9]+/' all_urls.txt 2>/dev/null | sort -u > api_endpoints.txt || > api_endpoints.txt

echo "   Params: $(wc -l < params.txt) unique | Detailed: $(wc -l < params_detailed.txt) | APIs: $(wc -l < api_endpoints.txt)"
send_telegram_message "Parameter Extraction completed. $(wc -l < params.txt) unique parameters."

# ==================== PHASE 9: PARAMETER DISCOVERY WITH ARJUN (ALL HOSTS) ====================
if [[ "$SKIP_ARJUN" -eq 0 ]] && command -v arjun >/dev/null 2>&1; then
  echo "[9/12] Parameter discovery with Arjun on ALL live hosts..."
  send_telegram_message "Starting *Parameter Discovery with Arjun* on ALL hosts..."

  mkdir -p arjun_results
  sem_init "${ARJUN_CONCURRENCY:-5}"  # Limit to 5 parallel arjun scans

  # Use alive_hosts.txt if exists, otherwise probe all_subs.txt
  if [[ -s alive_hosts.txt ]]; then
    input_file="alive_hosts.txt"
  elif [[ -s all_subs.txt ]]; then
    echo "   No alive hosts. Probing all subdomains with httpx..."
    > temp_arjun_targets.txt
    while IFS= read -r sub; do
      echo "https://$sub" >> temp_arjun_targets.txt
      echo "http://$sub" >> temp_arjun_targets.txt
    done < all_subs.txt
    httpx -l temp_arjun_targets.txt -silent -threads "$THREADS" -timeout 7 -o alive_hosts.txt >/dev/null 2>&1 || true
    rm -f temp_arjun_targets.txt
    [[ -s alive_hosts.txt ]] && input_file="alive_hosts.txt" || input_file=""
  else
    input_file=""
  fi

  if [[ -n "$input_file" && -s "$input_file" ]]; then
    total_hosts=$(wc -l < "$input_file")
    echo "   Scanning $total_hosts hosts with Arjun..."

    while IFS= read -r host; do
      sem_wait
      {
        host_clean=$(echo "$host" | sed 's|https\?://||; s|[:/]|_|g')
        output_file="arjun_results/${host_clean}.json"

        # Skip if already done
        [[ -f "$output_file" ]] && { sem_post; continue; }

        arjun -u "$host" \
          -oJ "$output_file" \
          -t "${ARJUN_THREADS:-10}" \
          -q 2>/dev/null || true

        sem_post
      } & disown
    done < "$input_file"

    wait
    sem_destroy

    scanned_count=$(find arjun_results -name "*.json" -type f | wc -l)
    echo "   Arjun complete: $scanned_count / $total_hosts hosts scanned"
    send_telegram_message "*Parameter Discovery (Arjun)* completed.\nScanned: $scanned_count hosts"
  else
    echo "   No live hosts to scan with Arjun"
    send_telegram_message "*Parameter Discovery (Arjun)* skipped — no live hosts"
  fi
else
  echo "[9/12] Arjun parameter discovery skipped"
  send_telegram_message "*Parameter Discovery with Arjun* skipped."
fi




# ==================== PHASE 10: ADVANCED FUZZING ON ALL SUBDOMAINS ====================
if [[ "$SKIP_FFUF" -eq 0 && -f "$FFUF_WORDLIST" && -s all_subs.txt ]]; then
  echo "Advanced directory and file fuzzing with ffuf on ALL subdomains..."
  send_telegram_message "Starting *Web Fuzzing with FFUF* on ALL subdomains..."

  mkdir -p ffuf_results
  sem_init "$FFUF_CONCURRENCY"

  # Prepare target list: http:// and https:// for every subdomain
  > ffuf_targets.txt
  while IFS= read -r sub; do
    echo "https://$sub" >> ffuf_targets.txt
    echo "http://$sub" >> ffuf_targets.txt
  done < all_subs.txt

  # Optional: Filter only reachable with httpx first (recommended)
  if command -v httpx >/dev/null 2>&1; then
    echo "   Probing all subdomains for reachability before fuzzing..."
    httpx -l ffuf_targets.txt -silent -threads "$THREADS" -timeout 7 -o ffuf_targets_alive.txt >/dev/null 2>&1 || true
    [[ -s ffuf_targets_alive.txt ]] && cp ffuf_targets_alive.txt ffuf_targets.txt
  fi

  # Main fuzzing loop
  while IFS= read -r target; do
    sem_wait
    {
      # Sanitize filename
      host_clean=$(echo "$target" | sed 's|https\?://||; s|[:/]|_|g')
      scheme=$(echo "$target" | cut -d: -f1)

      # Skip if already fuzzed
      [[ -f "ffuf_results/${host_clean}.json" ]] && { sem_post; continue; }

      ffuf -u "${target}/FUZZ" \
        -w "$FFUF_WORDLIST" \
        -t "$FFUF_THREADS" \
        -e "$FFUF_EXT" \
        -mc 200,201,202,203,204,301,302,401,403 \
        -fc 400,404,429 \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0.0.0 Safari/537.36" \
        -H "X-Forwarded-For: 127.0.0.1" \
        -H "X-Original-URL: /FUZZ" \
        -rate "$FFUF_RATE_LIMIT" \
        -timeout 10 \
        -o "ffuf_results/${host_clean}.json" \
        -of json \
        -silent 2>/dev/null || true

      # === Recursive Fuzzing (DEEP_SCAN) ===
      if [[ "$DEEP_SCAN" -eq 1 ]] && [[ -f "ffuf_results/${host_clean}.json" ]]; then
        jq -r '.results[]?.url' "ffuf_results/${host_clean}.json" 2>/dev/null | \
          grep -E '/$' | head -5 | while read -r dir; do
            dir_clean=$(echo "$dir" | sed 's|https\?://||; s|[:/]|_|g')
            [[ -f "ffuf_results/${dir_clean}_recursive.json" ]] && continue

            ffuf -u "${dir}FUZZ" \
              -w "$FFUF_WORDLIST" \
              -t "$FFUF_THREADS" \
              -recursion -recursion-depth 2 \
              -e "$FFUF_EXT" \
              -mc 200,201,202,203,204,301,302,401,403 \
              -fc 400,404,429 \
              -rate "$FFUF_RATE_LIMIT" \
              -o "ffuf_results/${dir_clean}_recursive.json" \
              -of json \
              -silent 2>/dev/null || true
          done
      fi

      # === Header Fuzzing (DEEP_SCAN only) ===
      if [[ "$DEEP_SCAN" -eq 1 ]] && [[ -f "$FFUF_HEADER_WORDLIST" ]]; then
        ffuf -u "$target" \
          -w "$FFUF_HEADER_WORDLIST:HEADER" \
          -H "HEADER: FUZZ" \
          -t "$FFUF_THREADS" \
          -mc 200,301,302,401,403 \
          -fc 400,404,429 \
          -rate "$FFUF_RATE_LIMIT" \
          -o "ffuf_results/${host_clean}_headers.json" \
          -of json \
          -silent 2>/dev/null || true
      fi

      sem_post
    } & disown
  done < ffuf_targets.txt

  wait
  sem_destroy

  # === Aggregate Results ===
  > ffuf_findings.txt
  find ffuf_results -name "*.json" ! -name "*_headers.json" ! -name "*_recursive.json" -type f 2>/dev/null | while read -r f; do
    jq -r '.results[]? | select(.status < 400 or .status == 401 or .status == 403) | "\(.status)\t\(.length)\t\(.url)"' "$f" 2>/dev/null
  done | sort -u >> ffuf_findings.txt

  > ffuf_headers.txt
  find ffuf_results -name "*_headers.json" -type f 2>/dev/null | while read -r f; do
    jq -r '.results[]? | select(.status < 400 or .status == 401 or .status == 403) | "\(.status)\t\(.input.HEADER)\t\(.url)"' "$f" 2>/dev/null
  done | sort -u >> ffuf_headers.txt

  total_hosts=$(wc -l < ffuf_targets.txt 2>/dev/null || echo 0)
  fuzzed_count=$(find ffuf_results -name "*.json" ! -name "*_recursive.json" ! -name "*_headers.json" | wc -l)
  echo "   Fuzzed $fuzzed_count / $total_hosts subdomains | Findings: $(wc -l < ffuf_findings.txt) | Header: $(wc -l < ffuf_headers.txt)"
  send_telegram_message "*Web Fuzzing (All Subdomains)* completed.\nFuzzed: $fuzzed_count hosts\nFindings: $(wc -l < ffuf_findings.txt)"
else
  echo "FFUF fuzzing skipped (missing wordlist, no subs, or SKIP_FFUF=1)"
  send_telegram_message "*Web Fuzzing* skipped."
fi


# ==================== PHASE 11: JAVASCRIPT ANALYSIS ====================
echo "📜 [11/12] JavaScript analysis and secret extraction..."
send_telegram_message "🔍 Starting *JavaScript Analysis*..."

grep -iE '\.js($|\?)' all_urls.txt 2>/dev/null | sort -u > js_files.txt || true

if [[ -s js_files.txt ]]; then
  mkdir -p js_analysis
  
  # Download and analyze JS files
  <js_files.txt head -50 | xargs -P10 -I{} bash -c '
    url="$1"
    hash=$(echo "$url" | md5sum | cut -d" " -f1)
    curl -sk -L "$url" -o "js_analysis/${hash}.js" 2>/dev/null || true
  ' _ {} || true
  
  # Extract endpoints from JS
  find js_analysis -name "*.js" -type f 2>/dev/null | xargs grep -hEo "https?://[^\"\']+" 2>/dev/null | \
    sort -u > js_endpoints.txt || true
  
  # Look for secrets/keys (expanded patterns)
  find js_analysis -name "*.js" -type f 2>/dev/null | xargs grep -hEi \
    'api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|aws[_-]?key|aws[_-]?secret|private[_-]?key|bearer[_-]?token|jwt[_-]?token|session[_-]?id|password|credential|token|key|secret|access_key' 2>/dev/null | \
    grep -v '//' | head -100 > js_secrets.txt || true
else
  >js_endpoints.txt
  >js_secrets.txt
fi

echo "   ✓ JS files: $(wc -l < js_files.txt) | Endpoints: $(wc -l < js_endpoints.txt) | Potential secrets: $(wc -l < js_secrets.txt)"
send_telegram_message "✅ *JavaScript Analysis* completed. Found $(wc -l < js_files.txt) JS files, $(wc -l < js_secrets.txt) potential secrets."

# ==================== PHASE 12: ADVANCED NUCLEI VULNERABILITY SCANNING ====================
if [[ "$SKIP_NUCLEI" -eq 0 && -d "$NUCLEI_TEMPLATES" ]]; then
  echo "💉 [12/12] Advanced Nuclei vulnerability scanning..."
  send_telegram_message "🔍 Starting *Vulnerability Scanning with Nuclei*..."
  
  # Update templates
  nuclei -update-templates -silent 2>/dev/null || true
  
  # Combine default and custom templates
  template_paths=("$NUCLEI_TEMPLATES")
  [[ -d "$CUSTOM_NUCLEI_TEMPLATES" ]] && template_paths+=("$CUSTOM_NUCLEI_TEMPLATES")
  
  # Scan hosts with advanced options
  if [[ -s alive_hosts.txt ]]; then
    nuclei -list alive_hosts.txt -t "${template_paths[*]}" -silent -c "$NUCLEI_THREADS" \
      -severity critical,high,medium,low -rl "$NUCLEI_RATE_LIMIT" \
      -etags fuzz,intrusive -es info -o nuclei_hosts.txt \
      -json -output nuclei_hosts.json 2>/dev/null || true
  fi
  
  # Scan URLs with advanced options
  if [[ -s all_urls.txt ]]; then
    nuclei -list all_urls.txt -t "${template_paths[*]}" -silent -c "$NUCLEI_THREADS" \
      -severity critical,high,medium,low -rl "$NUCLEI_RATE_LIMIT" \
      -etags fuzz,intrusive -es info -o nuclei_urls.txt \
      -json -output nuclei_urls.json 2>/dev/null || true
  fi
  
  # Separate by severity
  grep '\[critical\]' nuclei_hosts.txt nuclei_urls.txt 2>/dev/null > nuclei_critical.txt || true
  grep '\[high\]' nuclei_hosts.txt nuclei_urls.txt 2>/dev/null > nuclei_high.txt || true
  grep '\[medium\]' nuclei_hosts.txt nuclei_urls.txt 2>/dev/null > nuclei_medium.txt || true
  grep '\[low\]' nuclei_hosts.txt nuclei_urls.txt 2>/dev/null > nuclei_low.txt || true
  
  # Generate summary of findings
  {
    echo "Severity,Count"
    echo "Critical,$(wc -l < nuclei_critical.txt 2>/dev/null || echo 0)"
    echo "High,$(wc -l < nuclei_high.txt 2>/dev/null || echo 0)"
    echo "Medium,$(wc -l < nuclei_medium.txt 2>/dev/null || echo 0)"
    echo "Low,$(wc -l < nuclei_low.txt 2>/dev/null || echo 0)"
  } > nuclei_summary.csv
  
  echo "   ✓ Nuclei: Critical=$(wc -l < nuclei_critical.txt 2>/dev/null || echo 0), High=$(wc -l < nuclei_high.txt 2>/dev/null || echo 0), Medium=$(wc -l < nuclei_medium.txt 2>/dev/null || echo 0), Low=$(wc -l < nuclei_low.txt 2>/dev/null || echo 0)"
  send_telegram_message "✅ *Vulnerability Scanning with Nuclei* completed. Found $(wc -l < nuclei_critical.txt) critical, $(wc -l < nuclei_high.txt) high severity findings."
else
  echo "⏭️  [12/12] Nuclei scanning skipped"
  send_telegram_message "⏭️ *Vulnerability Scanning with Nuclei* skipped."
fi

# ==================== FINAL OUTPUT ====================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Complete! Recon finished for: $domain"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "📊 Summary:"
echo "   • Subdomains: $(wc -l < all_subs.txt 2>/dev/null || echo 0)"
echo "   • Alive Hosts: $(wc -l < alive_hosts.txt 2>/dev/null || echo 0)"
echo "   • URLs Collected: $(wc -l < all_urls.txt 2>/dev/null || echo 0)"
echo "   • Parameters Found: $(wc -l < params.txt 2>/dev/null || echo 0)"
echo "   • Open Ports: $(wc -l < open_ports.txt 2>/dev/null || echo 0)"
[[ -f nuclei_critical.txt ]] && echo "   • Critical Findings: $(wc -l < nuclei_critical.txt)"
[[ -f nuclei_high.txt ]] && echo "   • High Findings: $(wc -l < nuclei_high.txt)"
[[ -f ffuf_findings.txt ]] && echo "   • Fuzzing Findings: $(wc -l < ffuf_findings.txt)"
[[ -f dangling.txt ]] && echo "   • Potential Takeovers: $(wc -l < dangling.txt)"
echo
echo "📁 Output Directory: $OUT"
echo
echo "🔍 Key Files to Review:"
echo "   1. nuclei_critical.txt - Critical vulnerabilities (if any)"
echo "   2. nuclei_high.txt - High severity vulnerabilities"
echo "   3. ffuf_findings.txt - Directory and file fuzzing results"
echo "   4. ffuf_headers.txt - Header fuzzing results"
echo "   5. dangling.txt - Subdomain takeover candidates"
echo "   6. js_secrets.txt - Potential secrets in JavaScript"
echo "   7. params_detailed.txt - Parameters for manual testing"
echo "   8. technologies.txt - Technology stack"
echo "   9. alive_hosts.txt - Live web hosts for further testing"
echo "   10. open_ports.txt - Open ports from all IPs"
echo
echo "⚡ Pro Tips:"
echo "   • Use DEEP_SCAN=1 for recursive fuzzing and full port scans"
echo "   • Review ffuf_findings.txt and ffuf_headers.txt for hidden endpoints"
echo "   • Check params_detailed.txt for injection testing"
echo "   • Investigate js_analysis/ folder for downloaded JS files"
echo "   • Screenshots are in screenshots/ (if enabled)"
echo "   • Use nuclei_*.json for detailed vulnerability analysis"
echo "   • Combine nuclei_summary.csv with external tools for further analysis"
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Send Telegram notification: Scan completed
summary="📊 *RetroX Recon Summary* for $domain:\n"
summary="$summary- Subdomains: $(wc -l < all_subs.txt 2>/dev/null || echo 0)\n"
summary="$summary- Alive Hosts: $(wc -l < alive_hosts.txt 2>/dev/null || echo 0)\n"
summary="$summary- URLs Collected: $(wc -l < all_urls.txt 2>/dev/null || echo 0)\n"
summary="$summary- Parameters Found: $(wc -l < params.txt 2>/dev/null || echo 0)\n"
summary="$summary- Open Ports: $(wc -l < open_ports.txt 2>/dev/null || echo 0)\n"
[[ -f nuclei_critical.txt ]] && summary="$summary- Critical Findings: $(wc -l < nuclei_critical.txt)\n"
[[ -f nuclei_high.txt ]] && summary="$summary- High Findings: $(wc -l < nuclei_high.txt)\n"
[[ -f ffuf_findings.txt ]] && summary="$summary- Fuzzing Findings: $(wc -l < ffuf_findings.txt)\n"
[[ -f dangling.txt ]] && summary="$summary- Potential Takeovers: $(wc -l < dangling.txt)\n"
summary="$summary\n*Output Directory*: $OUT"
send_telegram_message "✅ *RetroX Recon Completed* at $(date)\n$summary"

cd - >/dev/null
