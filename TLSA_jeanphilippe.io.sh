#!/bin/bash

# Never echo secret-bearing shell expansions, including when invoked with -x.
set +x

# Script variables
CF_API_TOKEN="${CF_API_TOKEN:-}"
CF_API_TOKEN_FILE="${CF_API_TOKEN_FILE:-}"
CF_ZONE_ID="${CF_ZONE_ID:-}" # Set your Cloudflare DNS zone ID
SUBDOMAINS=( # Add your domains names
  ""
  ""
  ""
  ""
  ""
)
LOG_FILE="/var/log/letsencrypt/update_tlsa.log"
TIMEOUT=30  # Timeout for API requests (in seconds)
MAX_RETRIES=3  # Maximum retries in case of failure

# Colors for displaying in Shell
WHITE='\033[1;37m'
GREEN='\033[1;92m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

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

  # The token is embedded in a quoted curl config directive. Reject characters
  # which could escape that directive or introduce a second config option.
  if [[ -z "$CF_API_TOKEN" || "$CF_API_TOKEN" == *[[:cntrl:]]* || "$CF_API_TOKEN" == *\"* || "$CF_API_TOKEN" == *\\* ]]; then
    echo "ERROR: The Cloudflare token is missing or contains invalid characters." >&2
    return 1
  fi
  # Do not pass an exported token through the environment of child processes.
  export -n CF_API_TOKEN
}

# Script prerequisites initial check
function check_prerequisites {
  for cmd in curl jq tlsa; do
    if ! command -v "$cmd" &> /dev/null; then
      echo -e "${RED}[$(date)] ERROR: The command $cmd is required but not found. Exiting.${NC}"
      exit 1
    fi
  done

  load_api_token || exit 1

  if [ -z "$CF_ZONE_ID" ]; then
    echo -e "${RED}[$(date)] ERROR: CF_ZONE_ID is not set. Exiting.${NC}"
    exit 1
  fi
}

# Centralized function for sending API requests
function send_request {
  local METHOD=$1
  local URL=$2
  local DATA=$3

  # printf is a shell builtin; curl reads the sensitive header from stdin and
  # never receives it in its process arguments or inherited environment.
  if ! RESPONSE=$(printf 'header = "Authorization: Bearer %s"\n' "$CF_API_TOKEN" | \
    curl -s --config - --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
      -w "%{http_code}" -X "$METHOD" "$URL" \
      -H "Content-Type: application/json" --data "$DATA"); then
    echo "[$(date)] ERROR: Cloudflare request failed." >> "$LOG_FILE"
    return 1
  fi

  if (( ${#RESPONSE} < 3 )); then
    echo "[$(date)] ERROR: Invalid Cloudflare response." >> "$LOG_FILE"
    return 1
  fi
  HTTP_CODE="${RESPONSE: -3}"
  BODY="${RESPONSE:0:${#RESPONSE}-3}"
  if [[ ! "$HTTP_CODE" =~ ^[0-9]{3}$ ]]; then
    echo "[$(date)] ERROR: Invalid Cloudflare response status." >> "$LOG_FILE"
    return 1
  fi

  if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
    # An HTTP success alone does not mean Cloudflare accepted the operation.
    # Require exactly one JSON object with an explicit success flag.
    if ! printf '%s' "$BODY" | jq -es 'length == 1 and (.[0] | type == "object" and .success == true)' >/dev/null 2>&1; then
      echo "[$(date)] ERROR: Cloudflare returned an unsuccessful or invalid response." >> "$LOG_FILE"
      return 1
    fi
    printf '%s\n' "$BODY"
  else
    echo "[$(date)] ERROR: Cloudflare request returned HTTP $HTTP_CODE." >> "$LOG_FILE"
    return 1
  fi
}

# Step management with numbering
function step {
  local STEP_NUMBER=$1
  local MESSAGE=$2
  echo -e "${BLUE}[Step $STEP_NUMBER]${NC} $MESSAGE"
}

# Errors handling
function error_exit {
  echo -e "${RED}[$(date)] **TLSA RECORD UPDATE HAD FAILED**${NC}"
  exit 1
}

# Log rotation
function rotate_logs {
  if [ -f "$LOG_FILE" ] && [ "$(stat --format=%s "$LOG_FILE")" -ge 1048576 ]; then
    mv "$LOG_FILE" "$LOG_FILE.$(date +%Y%m%d%H%M%S)"
    echo "[$(date)] INFO: Log file rotated." > "$LOG_FILE"
  fi
}

# Verify & Delete existing Cloudflare TLSA records
function delete_tlsa_records {
  local SUBDOMAIN=$1
  local EXISTING_RECORDS RECORD_IDS RECORD_ID DELETE_RESULT
  step 1 "Deleting old TLSA records for $SUBDOMAIN."

  if ! EXISTING_RECORDS=$(send_request "GET" "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?type=TLSA&name=_443._tcp.$SUBDOMAIN" ""); then
    echo "[$(date)] ERROR: Failed to retrieve existing TLSA records."
    return 1
  fi

  # Treat malformed, unsuccessful, or paginated responses as failures rather
  # than claiming that no records exist or updating an incomplete result set.
  if ! RECORD_IDS=$(printf '%s' "$EXISTING_RECORDS" | jq -er '
    if .success == true and (.result | type == "array") and
       (.result_info.total_pages | type == "number" and . >= 0 and . <= 1 and floor == .) and
       all(.result[]; (.id | type == "string" and test("^[0-9a-f]{32}$")))
    then [.result[].id] | join("\n")
    else error("invalid TLSA record listing") end
  ' 2>/dev/null); then
    echo "[$(date)] ERROR: Invalid or incomplete TLSA record listing."
    return 1
  fi
  if [ -z "$RECORD_IDS" ]; then
    echo -e "${GREEN}[$(date)] No TLSA records to delete for $SUBDOMAIN.${NC}"
    return
  fi

  for RECORD_ID in $RECORD_IDS; do
    echo "[$(date)] Deleting TLSA record $RECORD_ID for $SUBDOMAIN..."
    DELETE_RESULT=$(send_request "DELETE" "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$RECORD_ID" "")
    if [ $? -eq 0 ]; then
      echo -e "${GREEN}[$(date)] TLSA record $RECORD_ID deleted.${NC}"
    else
      echo -e "${RED}[$(date)] ERROR: Failed to delete record $RECORD_ID.${NC}"
      return 1
    fi
  done
}

# Create a new TLSA record in Cloudflare DNS zone
function create_tlsa_record {
  local SUBDOMAIN=$1
  step 2 "Creating a new TLSA record for $SUBDOMAIN."

  if [ "$SUBDOMAIN" == "share.jeanphilippe.io" ]; then
    TLSA_RAW_OUTPUT=$(tlsa --create -4 "$SUBDOMAIN" --ca-cert /etc/letsencrypt/live/share.jeanphilippe.io/ -u 3 -s 1 -m 1 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$TLSA_RAW_OUTPUT" ]; then
      echo -e "${YELLOW}[$(date)] Let's Encrypt method failed. Switching to standard method.${NC}"
      TLSA_RAW_OUTPUT=$(tlsa --create "$SUBDOMAIN" -u 3 -s 1 -m 1)
    fi
  else
    TLSA_RAW_OUTPUT=$(tlsa --create "$SUBDOMAIN" -u 3 -s 1 -m 1)
  fi

  TLSA_HASH=$(echo "$TLSA_RAW_OUTPUT" | grep "IN TLSA" | awk '{print $NF}' | head -n 1)
  if [ -z "$TLSA_HASH" ]; then
    error_exit "Failed to generate TLSA hash for $SUBDOMAIN"
  fi

  # Generate JSON for Cloudfare API
  JSON_DATA=$(jq -n \
    --arg type "TLSA" \
    --arg name "_443._tcp.$SUBDOMAIN" \
    --arg usage "3" \
    --arg selector "1" \
    --arg matching_type "1" \
    --arg certificate "$TLSA_HASH" \
    '{
      type: $type,
      name: $name,
      data: {
        usage: ($usage | tonumber),
        selector: ($selector | tonumber),
        matching_type: ($matching_type | tonumber),
        certificate: $certificate
      }
    }'
  )

  ADD_RESULT=$(send_request "POST" "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" "$JSON_DATA")
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}[$(date)] New TLSA record successfully added for $SUBDOMAIN.${NC}"
  else
    echo -e "${RED}[$(date)] ERROR: Failed to create TLSA record for $SUBDOMAIN.${NC}"
    return 1
  fi
}

function main {
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
  echo "Usage: $0"
  echo "Set CF_ZONE_ID and CF_API_TOKEN, or use an owner-only CF_API_TOKEN_FILE."
  echo "This script updates TLSA records in Cloudflare for the configured subdomains."
  return 0
fi

# Logging
exec > >(tee -a "$LOG_FILE") 2>&1

check_prerequisites

# Rotate logs
rotate_logs

# Start measuring execution time
START_TIME=$(date +%s)

# Display the startup message
echo -e "${WHITE}**STARTING TLSA RECORD UPDATE**${NC}"

# Process each Cloudflare subdomain
for SUBDOMAIN in "${SUBDOMAINS[@]}"; do
  echo -e "${YELLOW}[$(date)] Starting process for $SUBDOMAIN...${NC}"
  delete_tlsa_records "$SUBDOMAIN" || error_exit "Deletion failed for $SUBDOMAIN"
  create_tlsa_record "$SUBDOMAIN" || error_exit "Creation failed for $SUBDOMAIN"
  echo -e "${GREEN}[$(date)] Finished processing for $SUBDOMAIN.${NC}"
done

# End measuring execution time
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
echo -e "${GREEN}[$(date)] TLSA records update had been successfully completed in ${DURATION}s.${NC}"
echo -e "${WHITE}**ENDING TLSA RECORD UPDATE**${NC}"

}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
