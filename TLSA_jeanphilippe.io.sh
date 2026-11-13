#!/bin/bash
############################################
# TLSA Update script for Cloudflare API
############################################

# Publish the SHA-256 fingerprint of each HTTPS server public key as a TLSA
# 3 1 1 record. Intended for a Certbot deploy hook or a manual run after review.
# Review certificate sources and paths before enabling. Delete followed by
# create is not atomic: failures can leave records absent. DNS caches and DNSSEC
# validation are not checked. Certbot does not detect independent OVH renewals.
# Disable shell tracing before reading secrets, even if Bash was invoked with -x.
set +x

############################################
# Script variables
############################################

# Set the zone ID locally or in the hook environment. Supply either a token
# variable or a private token file, never both. The file contains only the raw
# token and must be owned by the executing user. Interactive shell variables are
# not automatically inherited by a separately scheduled Certbot process.
CF_API_TOKEN="${CF_API_TOKEN:-}"
CF_API_TOKEN_FILE="${CF_API_TOKEN_FILE:-}"
CF_ZONE_ID="${CF_ZONE_ID:-}" # Set locally or provide through the hook environment.
if [[ -z "$CF_API_TOKEN" && -z "$CF_API_TOKEN_FILE" ]]; then
  CF_API_TOKEN_FILE="/etc/letsencrypt/renewal-hooks/deploy/cloudflare-tlsa.token"
fi
# List fully qualified hostnames to manage. All entries are checked before a
# real update starts; a preflight failure stops the operation before changes.
SUBDOMAINS=(
  "jeanphilippe.io"
  "monportfolio.jeanphilippe.io"
  "myportfolio.jeanphilippe.io"
  "share.jeanphilippe.io"
  "www.jeanphilippe.io"
)
# The local share certificate is independently checked against the HTTPS endpoint.
# OVH-managed certificates are obtained from the public endpoint: publication
# trusts the local PKIX trust store and the single endpoint reached at each check.
# This does not independently authenticate a new key against an existing TLSA.
# A different CDN edge, IPv4/IPv6 address or server can present another key.
declare -A CERTIFICATE_SOURCES=(
  ["jeanphilippe.io"]="public"
  ["monportfolio.jeanphilippe.io"]="public"
  ["myportfolio.jeanphilippe.io"]="public"
  ["share.jeanphilippe.io"]="local"
  ["www.jeanphilippe.io"]="public"
)
# Set a local path for every domain whose source is "local".
declare -A CERTIFICATE_PATHS=(
  ["share.jeanphilippe.io"]="/etc/letsencrypt/live/share.jeanphilippe.io/cert.pem"
)
LOG_FILE="${LOG_FILE:-/var/log/letsencrypt/update_tlsa.log}"
# TIMEOUT bounds network attempts in seconds. MAX_RETRIES bounds safe reads and
# confirmation polling; failed or ambiguous writes are not blindly repeated.
TIMEOUT="${TIMEOUT:-30}"
MAX_RETRIES="${MAX_RETRIES:-3}"
LOCK_DIR="${OKURU_TLSA_LOCK_DIR:-/run/lock/okuru-tlsa}"
LOG_TLSA=false
DRY_RUN=false
DIAGNOSTIC=false

############################################
# Usage / args
############################################

# --dry-run previews changes; --diagnostic reports each domain. Both modes query
# Cloudflare and HTTPS endpoints and take a local lock, but do not change DNS.
# Neither checks DNSSEC nor authoritative propagation or resolver caches.

function usage {
  echo "Usage: $0 [-log|--log-tlsa] [--dry-run|--diagnostic] [-h|--help]"
  echo "  --log-tlsa  Show certificate diagnostics (compatibility option)."
  echo "  --dry-run   Inspect certificates and Cloudflare records without modifying DNS."
  echo "  --diagnostic  Report each domain's certificate source and Cloudflare status without modifying DNS."
  echo "Set CF_ZONE_ID and either CF_API_TOKEN_FILE or CF_API_TOKEN."
  echo "Review CERTIFICATE_SOURCES and CERTIFICATE_PATHS against the actual endpoints."
  echo "Public checks also trust the system CA store and only the endpoint reached."
}

############################################
# Token handling and prerequisites
############################################

# Reject competing sources, symbolic links, files owned by another user and
# files accessible to group or others. Mode 0600 is suitable for a root hook.
# Reject characters that could inject curl configuration options. Removing the
# export flag keeps the token out of child process environments.

function load_api_token {
  if [[ -n "$CF_API_TOKEN_FILE" ]]; then
    if [[ -n "$CF_API_TOKEN" || ! -f "$CF_API_TOKEN_FILE" || -L "$CF_API_TOKEN_FILE" || ! -r "$CF_API_TOKEN_FILE" || ! -O "$CF_API_TOKEN_FILE" ]]; then
      echo "ERROR: Supply one readable, owner-controlled token file or one token variable." >&2
      return 1
    fi
    local mode
    mode=$(stat -c '%a' -- "$CF_API_TOKEN_FILE" 2>/dev/null || stat -f '%Lp' "$CF_API_TOKEN_FILE" 2>/dev/null) || return 1
    if [[ ! "$mode" =~ ^[0-7]{3,4}$ ]] || (( (8#$mode & 077) != 0 )); then
      echo "ERROR: The token file must not be accessible to group or other users." >&2
      return 1
    fi
    CF_API_TOKEN=$(< "$CF_API_TOKEN_FILE")
  fi
  if [[ -z "$CF_API_TOKEN" || "$CF_API_TOKEN" == *[[:cntrl:]]* || "$CF_API_TOKEN" == *\"* || "$CF_API_TOKEN" == *\\* ]]; then
    echo "ERROR: Cloudflare token missing or invalid." >&2
    return 1
  fi
  export -n CF_API_TOKEN
}

# Verify required tools, zone ID and retry settings before making API requests.

function check_prerequisites {
  local cmd
  for cmd in curl jq openssl stat timeout awk flock; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: Required command $cmd not found." >&2; return 1; }
  done
  [[ "$CF_ZONE_ID" =~ ^[[:xdigit:]]{32}$ ]] || { echo "ERROR: CF_ZONE_ID must be a 32-character hexadecimal zone ID." >&2; return 1; }
  [[ "$TIMEOUT" =~ ^[1-9][0-9]*$ && "$MAX_RETRIES" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: Invalid timeout or retry count." >&2; return 1; }
  load_api_token
}

############################################
# Log rotation
############################################

# Create the log directory if needed and rotate the log at 1 MiB. Actual updates
# write to this log; dry-run and diagnostic output remains on the console.

function rotate_logs {
  local log_dir timestamp size
  log_dir=$(dirname "$LOG_FILE") || return 1
  mkdir -p -- "$log_dir" || return 1
  if [[ -f "$LOG_FILE" ]]; then
    size=$(stat --format=%s "$LOG_FILE") || return 1
    if (( size >= 1048576 )); then
      timestamp=$(date +%Y%m%d%H%M%S)
      mv -- "$LOG_FILE" "${LOG_FILE}.${timestamp}" || return 1
    fi
  fi
}

############################################
# HTTP requests with timeout & retries
############################################

# Feed the bearer header to curl through standard input rather than arguments.
# Ignore implicit curl configuration and proxy settings, and require HTTPS.
# Check the HTTP status and Cloudflare JSON success flag. Retry safe GETs for
# temporary errors or rate limiting, but never blindly repeat an ambiguous
# DELETE or POST: the operation may already have taken effect.

function send_request {
  local method=$1 url=$2 data=${3:-} max_attempts=${4:-$MAX_RETRIES} attempt=1 response body http_code transport_ok
  while (( attempt <= max_attempts )); do
    echo "[$(date)] HTTP $method attempt $attempt" >&2
    transport_ok=true
    if [[ -n "$data" ]]; then
      response=$(printf 'header = "Authorization: Bearer %s"\n' "$CF_API_TOKEN" | curl -q -s --config - --noproxy '*' --proto '=https' --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -w '%{http_code}' -X "$method" "$url" -H 'Content-Type: application/json' --data "$data") || transport_ok=false
    else
      response=$(printf 'header = "Authorization: Bearer %s"\n' "$CF_API_TOKEN" | curl -q -s --config - --noproxy '*' --proto '=https' --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -w '%{http_code}' -X "$method" "$url" -H 'Content-Type: application/json') || transport_ok=false
    fi
    if [[ "$transport_ok" == true && ${#response} -ge 3 ]]; then
      http_code=${response: -3}
      body=${response:0:${#response}-3}
      if [[ "$http_code" =~ ^[0-9]{3}$ ]] && (( 10#$http_code >= 200 && 10#$http_code < 300 )); then
        if printf '%s' "$body" | jq -es 'length == 1 and (.[0] | type == "object" and .success == true)' >/dev/null 2>&1; then
          printf '%s\n' "$body"
          return 0
        fi
        echo "ERROR: Cloudflare returned an invalid or unsuccessful response." >&2
        return 1
      fi
    else
      http_code="000"
    fi
    echo "ERROR: Cloudflare request failed (HTTP ${http_code:-unknown})." >&2
    if [[ "$method" != GET || ! "$http_code" =~ ^[0-9]{3}$ ]] || (( 10#$http_code != 0 && 10#$http_code != 429 && 10#$http_code < 500 )); then
      [[ "$method" == GET ]] || echo "ERROR: Mutation outcome may be unknown; verify Cloudflare before retrying." >&2
      return 1
    fi
    (( attempt++ ))
    if (( attempt <= max_attempts )); then sleep 2; fi
  done
  echo "ERROR: GET failed after $max_attempts attempts." >&2
  return 1
}

############################################
# Certificate validation and TLSA fingerprints
############################################

# For a local certificate, check expiration and hostname separately, then hash
# its DER-encoded Subject Public Key Info with SHA-256. Separate checks matter:
# combining OpenSSL options may cause one of the checks to be ignored.

function calculate_tlsa_hash {
  local domain=$1 cert=${CERTIFICATE_PATHS[$1]:-} hash host_output
  [[ -n "$cert" && -f "$cert" && -r "$cert" ]] || { echo "ERROR: No readable configured certificate for $domain." >&2; return 1; }
  if [[ "$LOG_TLSA" == true ]]; then
    openssl x509 -in "$cert" -noout -checkend 0 >&2 || return 1
    host_output=$(openssl x509 -in "$cert" -noout -checkhost "$domain") || return 1
    printf '%s\n' "$host_output" >&2
  else
    openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1 || { echo "ERROR: Certificate expired or invalid for $domain." >&2; return 1; }
    host_output=$(openssl x509 -in "$cert" -noout -checkhost "$domain" 2>/dev/null) || return 1
  fi
  # OpenSSL 3.0 can return exit 0 even when the hostname does not match.
  [[ "$host_output" == "Hostname $domain does match certificate" ]] || { echo "ERROR: Certificate does not match $domain or output is unrecognized." >&2; return 1; }
  hash=$(set -o pipefail; openssl x509 -in "$cert" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -r 2>/dev/null) || return 1
  hash=${hash%% *}
  [[ "$hash" =~ ^[[:xdigit:]]{64}$ ]] || { echo "ERROR: Invalid SHA-256 SPKI fingerprint for $domain." >&2; return 1; }
  printf '%s\n' "${hash,,}"
}

# Authenticate one public HTTPS endpoint using SNI, hostname and certificate
# chain checks. Hash the public key of the certificate actually observed. One
# connection cannot establish what other addresses or CDN edges present; public
# sources rely on the system trust store and the endpoint reached.

function served_tlsa_hash {
  local domain=$1 output pem hash
  if [[ "$LOG_TLSA" == true ]]; then
    output=$(timeout "$TIMEOUT" openssl s_client -connect "$domain:443" -servername "$domain" -verify_return_error -verify_hostname "$domain" -showcerts </dev/null) || return 1
  else
    output=$(timeout "$TIMEOUT" openssl s_client -connect "$domain:443" -servername "$domain" -verify_return_error -verify_hostname "$domain" -showcerts </dev/null 2>/dev/null) || return 1
  fi
  pem=$(printf '%s\n' "$output" | awk '/-----BEGIN CERTIFICATE-----/{if (!seen) {seen=1; active=1}} active {print} /-----END CERTIFICATE-----/{if (active) exit}')
  [[ -n "$pem" ]] || return 1
  hash=$(set -o pipefail; printf '%s\n' "$pem" | openssl x509 -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -r 2>/dev/null) || return 1
  hash=${hash%% *}
  [[ "$hash" =~ ^[[:xdigit:]]{64}$ ]] || return 1
  printf '%s\n' "${hash,,}"
}

# Retry failed public TLS checks up to the configured attempt limit.

function retry_served_tlsa_hash {
  local domain=$1 attempt=1 result
  while (( attempt <= MAX_RETRIES )); do
    if result=$(served_tlsa_hash "$domain"); then printf '%s\n' "$result"; return 0; fi
    (( attempt++ ))
    if (( attempt <= MAX_RETRIES )); then sleep 2; fi
  done
  return 1
}

############################################
# Cloudflare TLSA record validation
############################################

# Accept either the structured data or formatted content representation. If
# both are present, require agreement; reject missing or inconsistent data.
# TLSA 3 1 1 is a DANE end-entity public-key association using SHA-256.
TLSA_JQ_LIBRARY='
def normal_data:
  if type != "object" then error("invalid data") else
    if (.usage | type) == "number" and (.selector | type) == "number" and
       (.matching_type | type) == "number" and (.certificate | type) == "string" and
       (.certificate | test("^[0-9a-fA-F]+$")) then
      {usage:.usage,selector:.selector,matching_type:.matching_type,certificate:(.certificate | ascii_downcase)}
    else error("invalid data") end
  end;
def normal_content:
  if type != "string" then error("invalid content") else
    if test("^[0-9]+[ \t]+[0-9]+[ \t]+[0-9]+[ \t]+[0-9a-fA-F]+$") then
      capture("^(?<u>[0-9]+)[ \t]+(?<s>[0-9]+)[ \t]+(?<m>[0-9]+)[ \t]+(?<c>[0-9a-fA-F]+)$") |
      {usage:(.u|tonumber),selector:(.s|tonumber),matching_type:(.m|tonumber),certificate:(.c|ascii_downcase)}
    else error("invalid content") end
  end;
def tlsa_normal:
  (if .data != null then (.data | normal_data) else null end) as $data |
  (if .content != null then (.content | normal_content) else null end) as $content |
  if $data == null and $content == null then error("missing TLSA data")
  elif $data != null and $content != null and $data != $content then error("inconsistent TLSA data")
  else ($data // $content) end;
def valid_norm:
  (.usage | type == "number" and floor == . and . >= 0 and . <= 3) and
  (.selector | type == "number" and floor == . and . >= 0 and . <= 1) and
  (.matching_type | type == "number" and floor == . and . >= 0 and . <= 2) and
  (.certificate | type == "string" and test("^([0-9a-f]{2})+$")) and
  (if .matching_type == 1 then (.certificate | length == 64)
   elif .matching_type == 2 then (.certificate | length == 128) else true end);
'

# Read one complete page for the requested name. Refuse malformed responses,
# unexpected names or IDs, and pagination that this script does not handle.

function fetch_tlsa_records {
  local domain=$1 max_attempts=${2:-$MAX_RETRIES} records
  records=$(send_request GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?type=TLSA&name=_443._tcp.$domain" "" "$max_attempts") || return 1
  if ! printf '%s' "$records" | jq -e --arg name "_443._tcp.$domain" "$TLSA_JQ_LIBRARY"'
    .success == true and (.result | type == "array") and
    (.result_info.total_pages | type == "number" and . >= 0 and . <= 1 and floor == .) and
    all(.result[]; (.id | type == "string" and test("^[0-9a-f]{32}$")) and .type == "TLSA" and (.name | ascii_downcase) == ($name | ascii_downcase) and (tlsa_normal | valid_norm))
  ' >/dev/null 2>&1; then
    echo "ERROR: Invalid, inconsistent, or paginated TLSA listing for $domain." >&2
    return 1
  fi
  printf '%s\n' "$records"
}

# A matching state has exactly one TLSA 3 1 1 record with the expected hash.
# Other states are reported by diagnostic or handled by the replacement flow.

function records_match {
  local records=$1 hash=$2
  printf '%s' "$records" | jq -e --arg hash "$hash" "$TLSA_JQ_LIBRARY"'
    (.result | length) == 1 and
    (.result[0] | tlsa_normal) == {usage:3,selector:1,matching_type:1,certificate:$hash}
  ' >/dev/null 2>&1
}

############################################
# Concurrent change detection
############################################

# Compare complete records rather than only IDs: another Cloudflare client can
# change a record in place between global preflight and a local DELETE. This
# detects observed changes but is not an atomic compare-and-delete operation.

function records_unchanged {
  local before=$1 after=$2 before_canonical after_canonical
  before_canonical=$(printf '%s' "$before" | jq -Sc '.result | sort_by(.id)') || return 1
  after_canonical=$(printf '%s' "$after" | jq -Sc '.result | sort_by(.id)') || return 1
  [[ "$before_canonical" == "$after_canonical" ]]
}

############################################
# Certificate source selection
############################################

# A local source must match the authenticated public endpoint. A public source
# uses that endpoint directly, as requested for the OVH-managed domains; it does
# not independently pin a newly observed key against an out-of-band reference.

function expected_tlsa_hash {
  local domain=$1 source=${CERTIFICATE_SOURCES[$1]:-} local_hash served_hash
  case "$source" in
    local)
      local_hash=$(calculate_tlsa_hash "$domain") || return 1
      served_hash=$(retry_served_tlsa_hash "$domain") || return 1
      [[ "$local_hash" == "$served_hash" ]] || {
        echo "ERROR: Local and publicly served certificates differ for $domain." >&2
        return 1
      }
      printf '%s\n' "$local_hash"
      ;;
    public)
      # HTTPS PKIX, hostname and SNI validation occurs in served_tlsa_hash.
      retry_served_tlsa_hash "$domain"
      ;;
    *)
      echo "ERROR: Missing or invalid certificate source for $domain." >&2
      return 1
      ;;
  esac
}

# Recheck the selected certificate against the fingerprint captured earlier.

function verify_current_endpoint {
  local domain=$1 expected=$2 current_hash
  current_hash=$(expected_tlsa_hash "$domain") || return 1
  [[ "$current_hash" == "$expected" ]]
}

# Poll Cloudflare for an empty or expected state without repeating a write. A
# confirmed API state does not prove DNS propagation or DNSSEC validation.

function await_records {
  local domain=$1 desired=$2 hash=${3:-} attempt=1 records
  while (( attempt <= MAX_RETRIES )); do
    if records=$(fetch_tlsa_records "$domain" 1); then
      if [[ "$desired" == empty ]] && printf '%s' "$records" | jq -e '(.result | length) == 0' >/dev/null 2>&1; then return 0; fi
      if [[ "$desired" == matching ]] && records_match "$records" "$hash"; then return 0; fi
    fi
    (( attempt++ ))
    if (( attempt <= MAX_RETRIES )); then sleep 2; fi
  done
  return 1
}

############################################
# Delete existing and create new TLSA records
############################################

# Main validates all certificates, endpoints, payloads and listings first.
# Recheck the endpoint and Cloudflare snapshot immediately before deletion.
# Delete old records, confirm their absence, create the new record and confirm
# the expected value. A failure after deletion can leave records absent; inspect
# Cloudflare promptly. This sequence does not guarantee an uninterrupted rollover.

function update_domain {
  local domain=$1 hash=$2 ids=$3 json=$4 previous=$5 current id post_ok=true
  if [[ "$DRY_RUN" == true ]]; then
    echo "DRY RUN: Would replace existing _443._tcp.$domain TLSA records with 3 1 1 $hash."
    return 0
  fi
  if ! verify_current_endpoint "$domain" "$hash"; then
    echo "ERROR: Certificate or served endpoint changed for $domain; no DNS changes made for this domain." >&2
    return 1
  fi
  current=$(fetch_tlsa_records "$domain") || { echo "ERROR: Cannot recheck Cloudflare records for $domain; no DNS changes made for this domain." >&2; return 1; }
  if ! records_unchanged "$previous" "$current"; then
    echo "ERROR: Cloudflare records changed during preflight for $domain; no DNS changes made for this domain." >&2
    return 1
  fi
  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    send_request DELETE "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$id" "" >/dev/null || { echo "ERROR: TLSA deletion failed or is uncertain; creation not attempted. Existing records may already have been removed." >&2; return 1; }
  done <<< "$ids"
  if ! await_records "$domain" empty; then
    echo "ERROR: Cannot confirm deletion for $domain; creation not attempted. Check Cloudflare immediately." >&2
    return 1
  fi
  send_request POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" "$json" >/dev/null || post_ok=false
  if ! await_records "$domain" matching "$hash"; then
    echo "ERROR: Cloudflare did not confirm exactly the expected TLSA for $domain; old records may be gone. Check Cloudflare immediately." >&2
    return 1
  fi
  if [[ "$post_ok" != true ]]; then
    echo "WARNING: POST response was ambiguous; expected record confirmed by Cloudflare GET for $domain." >&2
  fi
  if ! verify_current_endpoint "$domain" "$hash"; then
    echo "ERROR: Certificate or endpoint changed after publishing for $domain; DNS was modified. Check Cloudflare and the endpoint immediately." >&2
    return 1
  fi
  echo "[$(date)] Expected TLSA confirmed in Cloudflare for $domain; DNS propagation not checked."
}

############################################
# Process lock
############################################

# Hold an exclusive local lock for the run. It prevents another instance on
# this host from running simultaneously, but cannot lock other machines or the
# Cloudflare dashboard; snapshot comparison reduces but cannot eliminate races.

function acquire_lock {
  local mode
  command -v flock >/dev/null 2>&1 || { echo "ERROR: Required command flock not found." >&2; return 1; }
  [[ "$LOCK_DIR" == /* ]] || { echo "ERROR: Lock directory must be absolute." >&2; return 1; }
  mkdir -m 700 -- "$LOCK_DIR" 2>/dev/null || [[ -d "$LOCK_DIR" ]] || return 1
  [[ -d "$LOCK_DIR" && ! -L "$LOCK_DIR" && -O "$LOCK_DIR" ]] || { echo "ERROR: Unsafe lock directory." >&2; return 1; }
  mode=$(stat -c '%a' -- "$LOCK_DIR" 2>/dev/null || stat -f '%Lp' "$LOCK_DIR" 2>/dev/null) || return 1
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 077) == 0 )) || { echo "ERROR: Lock directory permissions must exclude group and others." >&2; return 1; }
  [[ ! -L "$LOCK_DIR/lock" ]] || { echo "ERROR: Unsafe lock file." >&2; return 1; }
  exec {TLSA_LOCK_FD}>>"$LOCK_DIR/lock" || return 1
  flock -n "$TLSA_LOCK_FD" || { echo "ERROR: Another TLSA update is already running." >&2; return 1; }
}

############################################
# MAIN
############################################

# Parse arguments, acquire the lock and check all domains before any real DNS
# update. Diagnostic continues across domain errors and returns failure if a
# domain cannot be checked or differs. Matching records are left unchanged.
# Run main in a subshell to release the lock on every exit path.

function main (
  while (( $# > 0 )); do
    case "$1" in
      -log|--log-tlsa) LOG_TLSA=true ;;
      --dry-run) DRY_RUN=true ;;
      --diagnostic) DIAGNOSTIC=true; DRY_RUN=true ;;
      -h|--help) usage; return 0 ;;
      *) echo "ERROR: Unknown option: $1" >&2; usage >&2; return 1 ;;
    esac
    shift
  done
  acquire_lock || return 1
  if [[ "$DRY_RUN" != true ]]; then
    rotate_logs || { echo "ERROR: Cannot prepare log." >&2; return 1; }
    # Open the log directly, so a failed redirection stops the update. A tee
    # process substitution can fail independently while DNS updates continue.
    exec >> "$LOG_FILE" 2>&1 || { echo "ERROR: Cannot write log." >&2; return 1; }
  fi
  check_prerequisites || return 1
  local start_time end_time domain hash records ids json diagnostic_issues=0
  local -A hashes listings payloads snapshots skip seen
  start_time=$(date +%s)
  echo "**STARTING TLSA RECORD UPDATE**"
  echo "Preflighting all configured domains before any DNS change."
  for domain in "${SUBDOMAINS[@]}"; do
    if [[ ! "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ || "$domain" == *..* || "$domain" == *.-* || "$domain" == *-.* || ${#domain} -gt 253 ]]; then
      echo "ERROR: Invalid domain: $domain." >&2
      if [[ "$DIAGNOSTIC" == true ]]; then ((diagnostic_issues++)); continue; else return 1; fi
    fi
    if [[ -n "${seen[$domain]+present}" ]]; then
      echo "ERROR: Duplicate domain $domain." >&2
      if [[ "$DIAGNOSTIC" == true ]]; then ((diagnostic_issues++)); continue; else return 1; fi
    fi
    seen[$domain]=yes
    if ! hash=$(expected_tlsa_hash "$domain"); then
      echo "ERROR: Cannot verify the configured certificate source for $domain; DNS unchanged." >&2
      if [[ "$DIAGNOSTIC" == true ]]; then ((diagnostic_issues++)); continue; else return 1; fi
    fi
    if ! records=$(fetch_tlsa_records "$domain"); then
      echo "ERROR: Cannot inspect Cloudflare records for $domain; DNS unchanged." >&2
      if [[ "$DIAGNOSTIC" == true ]]; then ((diagnostic_issues++)); continue; else return 1; fi
    fi
    if [[ "$DIAGNOSTIC" == true ]]; then
      echo "DIAGNOSTIC: $domain source=${CERTIFICATE_SOURCES[$domain]} HTTPS=verified fingerprint=$hash"
      if records_match "$records" "$hash"; then
        echo "DIAGNOSTIC: $domain Cloudflare=matching"
      elif printf '%s' "$records" | jq -e '(.result | length) == 0' >/dev/null 2>&1; then
        echo "DIAGNOSTIC: $domain Cloudflare=empty; an update is needed."
        ((diagnostic_issues++))
      else
        echo "DIAGNOSTIC: $domain Cloudflare=differs; an update is needed."
        ((diagnostic_issues++))
      fi
      continue
    fi
    ids=$(printf '%s' "$records" | jq -r '.result[].id') || return 1
    json=$(jq -n --arg name "_443._tcp.$domain" --arg hash "$hash" '{type:"TLSA",name:$name,data:{usage:3,selector:1,matching_type:1,certificate:$hash}}') || return 1
    hashes[$domain]=$hash
    listings[$domain]=$ids
    payloads[$domain]=$json
    snapshots[$domain]=$records
    if records_match "$records" "$hash"; then skip[$domain]=yes; else skip[$domain]=no; fi
  done
  if [[ "$DIAGNOSTIC" == true ]]; then
    echo "DIAGNOSTIC: DNS propagation and DNSSEC validation were not checked."
    echo "DIAGNOSTIC: Public certificate sources rely on the system PKIX trust store and the endpoint reached."
    if (( diagnostic_issues > 0 )); then
      echo "DIAGNOSTIC: $diagnostic_issues domain(s) need attention; no DNS records were changed." >&2
      return 1
    fi
    echo "DIAGNOSTIC: All configured domains match Cloudflare; no DNS records were changed."
    return 0
  fi
  for domain in "${SUBDOMAINS[@]}"; do
    if [[ "${skip[$domain]}" == yes ]]; then
      echo "Existing Cloudflare TLSA already matches $domain; no change."
      continue
    fi
    update_domain "$domain" "${hashes[$domain]}" "${listings[$domain]}" "${payloads[$domain]}" "${snapshots[$domain]}" || { echo "**TLSA RECORD UPDATE FAILED**" >&2; return 1; }
  done
  end_time=$(date +%s)
  echo "TLSA update completed in $((end_time-start_time))s."
  echo "**ENDING TLSA RECORD UPDATE**"
)

############################################
# Script entry point
############################################

# Do not execute the update when this file is sourced by the offline tests.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  # main runs in a subshell, so this shell retains Certbot's original stderr
  # even when the real run redirects its own output to the log.
  if ! main "$@"; then
    echo "ERROR: TLSA update failed. If logging was enabled, check $LOG_FILE." >&2
    exit 1
  fi
fi
