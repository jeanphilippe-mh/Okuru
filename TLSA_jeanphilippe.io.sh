#!/bin/bash

# Script variables
CF_API_TOKEN="" # Add your Cloudflare API Token
CF_ZONE_ID="" # Add your Cloudflare DNS zone ID
SUBDOMAINS=(
  "jeanphilippe.io"
  "monportfolio.jeanphilippe.io"
  "myportfolio.jeanphilippe.io"
  "share.jeanphilippe.io"
  "www.jeanphilippe.io"
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

# Logging
exec > >(tee -a "$LOG_FILE") 2>&1

# Script prerequisites initial check
function check_prerequisites {
  for cmd in curl jq tlsa; do
    if ! command -v "$cmd" &> /dev/null; then
      echo -e "${RED}[$(date)] ERROR: The command $cmd is required but not found. Exiting.${NC}"
      exit 1
    fi
  done

  if [ -z "$CF_API_TOKEN" ]; then
    echo -e "${RED}[$(date)] ERROR: CF_API_TOKEN is not set. Exiting.${NC}"
    exit 1
  fi

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

  RESPONSE=$(curl -s -w "%{http_code}" -X "$METHOD" "$URL" \
    -H "Authorization: Bearer $CF_API_TOKEN" \
    -H "Content-Type: application/json" \
    --data "$DATA")

  HTTP_CODE=$(echo "$RESPONSE" | tail -c 4)
  BODY=$(echo "$RESPONSE" | head -c -4)

  if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
    echo "$BODY"
  else
    echo "[$(date)] ERROR: HTTP $HTTP_CODE - $(echo "$BODY" | jq -r '.errors[].message')" >> "$LOG_FILE"
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
  step 1 "Deleting old TLSA records for $SUBDOMAIN."

  EXISTING_RECORDS=$(send_request "GET" "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?type=TLSA&name=_443._tcp.$SUBDOMAIN" "")

  RECORD_IDS=$(echo "$EXISTING_RECORDS" | jq -r '.result[].id // empty')
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

# Check prerequisites
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

# Display script usage --help
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
  echo -e "${WHITE}Usage: $0${NC}"
  echo "This script updates TLSA records in Cloudflare for the specified subdomains."
  exit 0
fi
