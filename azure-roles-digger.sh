#!/usr/bin/env bash
#
# ╔═══════════════════════════════════════════════════════════════════════════════╗
# ║                          azure-roles-digger.sh                                ║
# ║         Azure & Entra ID Role/Permission Discovery Tool                       ║
# ╚═══════════════════════════════════════════════════════════════════════════════╝
#
#
# DESCRIPTION:
#   Comprehensive role and permission discovery tool for Azure environments.
#   Given an Entra Object ID (user, service principal, or group), this script
#   discovers ALL effective permissions including:
#
#   - Direct Azure RBAC role assignments
#   - Inherited Azure RBAC roles (via group memberships)
#   - Entra ID directory roles (Global Admin, User Admin, etc.)
#   - PIM (Privileged Identity Management) eligible roles
#
# FEATURES:
#   - Automatic identity type detection (user/service principal/group)
#   - Transitive group membership discovery via Microsoft Graph API
#   - Full permission extraction (actions, notActions, dataActions, notDataActions)
#   - Beautiful table output (default) or JSON for scripting
#   - Selective discovery with skip flags
#   - Parallel subscription queries for improved performance
#   - Automatic PIM API version detection (uses latest stable version)
#   - Configurable timeouts to prevent hanging on slow/unresponsive APIs
#   - Input validation (UUID format checking)
#
# REQUIREMENTS:
#   - Azure CLI (az) - authenticated with appropriate permissions
#   - jq - JSON processor
#   - Bash 3.2+ (4.0+ recommended for best performance)
#   - timeout command (optional, from coreutils - enables timeout protection)
#
# PERMISSIONS NEEDED:
#   - Reader on Azure subscriptions (for RBAC queries)
#   - Directory.Read.All (for Graph API group membership)
#   - RoleManagement.Read.Directory (for Entra directory roles)
#   - Privileged Role Reader (for PIM queries)
#
# USAGE:
#   ./azure-roles-digger.sh [OPTIONS] [OBJECT_ID]
#
# OPTIONS:
#   --json          Output as JSON instead of tables (for scripting)
#   --skip-groups   Skip group membership and inherited role discovery
#   --skip-entra    Skip Entra ID directory role discovery
#   --skip-pim      Skip PIM eligible role discovery
#   --quiet         Suppress progress messages (only show final output)
#   --help, -h      Show help message
#
# EXAMPLES:
#   # Interactive mode - prompts for Object ID
#   ./azure-roles-digger.sh
#
#   # Direct with Object ID
#   ./azure-roles-digger.sh a1b2c3d4-e5f6-7890-abcd-ef1234567890
#
#   # JSON output for scripting
#   ./azure-roles-digger.sh --json a1b2c3d4-e5f6-7890-abcd-ef1234567890
#
#   # Skip PIM and Entra checks (faster, RBAC only)
#   ./azure-roles-digger.sh --skip-pim --skip-entra a1b2c3d4-e5f6-7890-abcd-ef1234567890
#
#   # Quiet mode with JSON (ideal for piping)
#   ./azure-roles-digger.sh --quiet --json $OBJ_ID | jq '.directAzureRBAC'
#
#   # With custom timeout (useful for slow networks)
#   AZ_CALL_TIMEOUT=60 ./azure-roles-digger.sh $OBJ_ID
#
#   # Force specific PIM API version
#   PIM_API_VERSION=2022-04-01-preview ./azure-roles-digger.sh $OBJ_ID
#
# ENVIRONMENT VARIABLES:
#   AZ_CALL_TIMEOUT       - Timeout in seconds for API calls (default: 30)
#   AZ_CALL_TIMEOUT_LONG  - Timeout for long operations like role lists (default: 60)
#   PIM_API_VERSION       - Override auto-detected PIM API version (default: auto-detect)
#
# OUTPUT STRUCTURE (JSON mode):
#   {
#     "identity": { "objectId", "type", "displayName" },
#     "directAzureRBAC": [ { "roleName", "scopes", "permissions": {...} } ],
#     "inheritedFromGroups": [ { "groupId", "groupName", "roles": [...] } ],
#     "entraDirectoryRoles": [ { "roleName", "assignmentType", "inheritedFrom" } ],
#     "pimEligible": {
#       "entraRoles": [ { "roleName", "status", "startDateTime", "endDateTime" } ],
#       "azureRBAC": [ { "roleName", "scope", "status" } ]
#     }
#   }
#
# AUTHOR: @fhd342gs
# ═══════════════════════════════════════════════════════════════════════════════


set -euo pipefail

# ============================================================================
# Configuration flags
# ============================================================================
SKIP_GROUPS=false
SKIP_ENTRA=false
SKIP_PIM=false
OUTPUT_JSON=false
QUIET_MODE=false
OBJ_ID=""

# ============================================================================
# Parse command-line arguments
# ============================================================================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-groups)
      SKIP_GROUPS=true
      shift
      ;;
    --skip-entra)
      SKIP_ENTRA=true
      shift
      ;;
    --skip-pim)
      SKIP_PIM=true
      shift
      ;;
    --json)
      OUTPUT_JSON=true
      shift
      ;;
    --quiet)
      QUIET_MODE=true
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [OPTIONS] [OBJECT_ID]"
      echo ""
      echo "Discover Azure RBAC and Entra ID roles for an identity."
      echo ""
      echo "Options:"
      echo "  --json          Output as JSON instead of tables"
      echo "  --skip-groups   Skip group inheritance discovery"
      echo "  --skip-entra    Skip Entra ID directory roles"
      echo "  --skip-pim      Skip PIM eligible roles"
      echo "  --quiet         Suppress progress messages"
      echo "  --help, -h      Show this help message"
      echo ""
      echo "Examples:"
      echo "  $0 a1b2c3d4-e5f6-7890-abcd-ef1234567890"
      echo "  $0 --json --skip-pim \$OBJECT_ID"
      echo "  $0 --quiet --json \$OBJECT_ID | jq '.directAzureRBAC'"
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
    *)
      OBJ_ID="$1"
      shift
      ;;
  esac
done

# ============================================================================
# Dependency checks
# ============================================================================
command -v az >/dev/null 2>&1 || { echo "Azure CLI (az) not found."; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq not found."; exit 1; }

# Check for timeout command (coreutils)
TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  # macOS with coreutils installed via brew
  TIMEOUT_CMD="gtimeout"
fi

# ============================================================================
# Configuration - Timeouts and API versions
# ============================================================================
# Default timeout for API calls (in seconds) - can be overridden via environment
AZ_CALL_TIMEOUT="${AZ_CALL_TIMEOUT:-30}"
AZ_CALL_TIMEOUT_LONG="${AZ_CALL_TIMEOUT_LONG:-60}"

# PIM API version - will be auto-detected if not set
PIM_API_VERSION="${PIM_API_VERSION:-}"

# Fallback API version if auto-detection fails
PIM_API_VERSION_FALLBACK="2020-10-01"

# ============================================================================
# Timeout wrapper for az commands
# ============================================================================
# Executes az command with timeout protection
# Usage: az_with_timeout <timeout_seconds> <az_args...>
# Returns: az command output, or empty string on timeout/failure
az_with_timeout() {
  local timeout_secs="$1"
  shift

  if [[ -n "$TIMEOUT_CMD" ]]; then
    $TIMEOUT_CMD "$timeout_secs" az "$@" 2>/dev/null
  else
    # No timeout available, run directly
    az "$@" 2>/dev/null
  fi
}

# Wrapper specifically for az rest calls
# Usage: az_rest_with_timeout <timeout_seconds> <method> <url> [extra_args...]
az_rest_with_timeout() {
  local timeout_secs="$1"
  local method="$2"
  local url="$3"
  shift 3

  if [[ -n "$TIMEOUT_CMD" ]]; then
    $TIMEOUT_CMD "$timeout_secs" az rest --method "$method" --url "$url" "$@" 2>/dev/null
  else
    az rest --method "$method" --url "$url" "$@" 2>/dev/null
  fi
}

# ============================================================================
# Auto-detect latest stable PIM API version
# ============================================================================
detect_pim_api_version() {
  local provider_info
  local api_versions
  local latest_stable

  # Query the Azure Resource Provider for Microsoft.Authorization
  provider_info=$(az_with_timeout "$AZ_CALL_TIMEOUT" provider show \
    --namespace Microsoft.Authorization \
    --query "resourceTypes[?resourceType=='roleEligibilityScheduleInstances'].apiVersions" \
    -o json 2>/dev/null || echo "null")

  if [[ "$provider_info" == "null" || -z "$provider_info" ]]; then
    # Fallback: try REST API directly
    provider_info=$(az_rest_with_timeout "$AZ_CALL_TIMEOUT" GET \
      "https://management.azure.com/providers/Microsoft.Authorization?api-version=2021-04-01" \
      2>/dev/null || echo '{}')

    api_versions=$(echo "$provider_info" | jq -r '
      .resourceTypes[]? |
      select(.resourceType == "roleEligibilityScheduleInstances") |
      .apiVersions[]?
    ' 2>/dev/null | head -20)
  else
    api_versions=$(echo "$provider_info" | jq -r '.[]?[]?' 2>/dev/null | head -20)
  fi

  if [[ -z "$api_versions" ]]; then
    echo "$PIM_API_VERSION_FALLBACK"
    return 0
  fi

  # Filter for stable versions (no -preview, -beta, -alpha suffix)
  # Sort by version (newest first) and take the first one
  latest_stable=$(echo "$api_versions" | grep -v -E '(-preview|-beta|-alpha)$' | sort -rV | head -1)

  if [[ -z "$latest_stable" ]]; then
    # If no stable version found, use the newest preview
    latest_stable=$(echo "$api_versions" | sort -rV | head -1)
  fi

  if [[ -z "$latest_stable" ]]; then
    echo "$PIM_API_VERSION_FALLBACK"
  else
    echo "$latest_stable"
  fi
}

# Initialize PIM API version (auto-detect if not set)
init_pim_api_version() {
  if [[ -z "$PIM_API_VERSION" ]]; then
    PIM_API_VERSION=$(detect_pim_api_version)
    log_progress "Auto-detected PIM API version: $PIM_API_VERSION"
  fi
}

# ============================================================================
# Bash version compatibility - readarray fallback for bash < 4.0
# ============================================================================
if ! declare -F readarray >/dev/null 2>&1; then
  # Provide readarray/mapfile fallback for bash 3.x
  readarray() {
    local _array_name=""
    local _line
    local -a _temp_array=()

    # Parse arguments (simplified: supports -t and array name)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -t) shift ;;  # -t strips trailing newlines (we do this by default with read)
        *)  _array_name="$1"; shift ;;
      esac
    done

    # Read lines into temp array
    while IFS= read -r _line || [[ -n "$_line" ]]; do
      _temp_array+=("$_line")
    done

    # Assign to target array using eval (necessary for dynamic array name)
    eval "$_array_name=(\"\${_temp_array[@]}\")"
  }
fi

# ============================================================================
# Logging helper (respects QUIET_MODE)
# ============================================================================
log() {
  if [[ "$QUIET_MODE" == "false" && "$OUTPUT_JSON" == "false" ]]; then
    echo "$@"
  fi
}

log_progress() {
  if [[ "$QUIET_MODE" == "false" && "$OUTPUT_JSON" == "false" ]]; then
    echo -e "\033[90m$@\033[0m"
  fi
}

# ============================================================================
# Table formatting functions
# ============================================================================
TABLE_WIDTH=90

print_header_box() {
  local title="$1"
  local title_len=${#title}
  local padding=$(( (TABLE_WIDTH - title_len - 2) / 2 ))
  local padding_r=$(( TABLE_WIDTH - title_len - 2 - padding ))

  echo "╔$(printf '═%.0s' $(seq 1 $TABLE_WIDTH))╗"
  echo "║$(printf ' %.0s' $(seq 1 $padding))$title$(printf ' %.0s' $(seq 1 $padding_r)) ║"
  echo "╚$(printf '═%.0s' $(seq 1 $TABLE_WIDTH))╝"
}

print_section_header() {
  local title="$1"
  local title_len=${#title}
  local padding=$(( (TABLE_WIDTH - title_len - 2) / 2 ))
  local padding_r=$(( TABLE_WIDTH - title_len - 2 - padding ))

  echo "┌$(printf '─%.0s' $(seq 1 $TABLE_WIDTH))┐"
  echo "│$(printf ' %.0s' $(seq 1 $padding))$title$(printf ' %.0s' $(seq 1 $padding_r)) │"
  echo "├$(printf '─%.0s' $(seq 1 $TABLE_WIDTH))┤"
}

print_section_footer() {
  echo "└$(printf '─%.0s' $(seq 1 $TABLE_WIDTH))┘"
}

print_row() {
  local content="$1"
  local content_len=${#content}
  local padding=$(( TABLE_WIDTH - content_len ))
  if (( padding < 0 )); then
    content="${content:0:$((TABLE_WIDTH-3))}..."
    padding=0
  fi
  echo "│ $content$(printf ' %.0s' $(seq 1 $((padding-1))))│"
}

print_scope_row() {
  local prefix="$1"
  local scope="$2"
  local prefix_len=${#prefix}
  local max_scope_len=$(( TABLE_WIDTH - prefix_len - 1 ))

  if (( ${#scope} <= max_scope_len )); then
    # Fits on one line
    local content="$prefix$scope"
    local padding=$(( TABLE_WIDTH - ${#content} ))
    echo "│ $content$(printf ' %.0s' $(seq 1 $((padding-1))))│"
  else
    # Need to wrap - print first part
    local first_part="${scope:0:$max_scope_len}"
    local content="$prefix$first_part"
    local padding=$(( TABLE_WIDTH - ${#content} ))
    echo "│ $content$(printf ' %.0s' $(seq 1 $((padding-1))))│"

    # Print remaining parts with indent
    local remaining="${scope:$max_scope_len}"
    local indent="$(printf ' %.0s' $(seq 1 $prefix_len))"
    while (( ${#remaining} > 0 )); do
      if (( ${#remaining} <= max_scope_len )); then
        content="$indent$remaining"
        padding=$(( TABLE_WIDTH - ${#content} ))
        echo "│ $content$(printf ' %.0s' $(seq 1 $((padding-1))))│"
        break
      else
        first_part="${remaining:0:$max_scope_len}"
        content="$indent$first_part"
        padding=$(( TABLE_WIDTH - ${#content} ))
        echo "│ $content$(printf ' %.0s' $(seq 1 $((padding-1))))│"
        remaining="${remaining:$max_scope_len}"
      fi
    done
  fi
}

print_kv_row() {
  local key="$1"
  local value="$2"
  local key_width=16
  local value_width=$(( TABLE_WIDTH - key_width - 5 ))

  if (( ${#value} > value_width )); then
    value="${value:0:$((value_width-3))}..."
  fi

  printf "│  %-${key_width}s : %-${value_width}s │\n" "$key" "$value"
}

print_table_separator() {
  echo "├$(printf '─%.0s' $(seq 1 $TABLE_WIDTH))┤"
}

print_two_col_header() {
  local col1="$1"
  local col2="$2"
  local col1_width=28
  local col2_width=$(( TABLE_WIDTH - col1_width - 5 ))
  printf "│ %-${col1_width}s │ %-${col2_width}s│\n" "$col1" "$col2"
  echo "├$(printf '─%.0s' $(seq 1 $((col1_width+2))))┼$(printf '─%.0s' $(seq 1 $((col2_width+1))))┤"
}

print_two_col_row() {
  local col1="$1"
  local col2="$2"
  local col1_width=28
  local col2_width=$(( TABLE_WIDTH - col1_width - 5 ))

  if (( ${#col1} > col1_width )); then
    col1="${col1:0:$((col1_width-3))}..."
  fi
  if (( ${#col2} > col2_width )); then
    col2="${col2:0:$((col2_width-3))}..."
  fi

  printf "│ %-${col1_width}s │ %-${col2_width}s│\n" "$col1" "$col2"
}

print_three_col_header() {
  local col1="$1"
  local col2="$2"
  local col3="$3"
  local col1_width=30
  local col2_width=14
  local col3_width=$(( TABLE_WIDTH - col1_width - col2_width - 7 ))
  printf "│ %-${col1_width}s │ %-${col2_width}s│ %-${col3_width}s│\n" "$col1" "$col2" "$col3"
  echo "├$(printf '─%.0s' $(seq 1 $((col1_width+2))))┼$(printf '─%.0s' $(seq 1 $((col2_width+1))))┼$(printf '─%.0s' $(seq 1 $((col3_width+1))))┤"
}

print_three_col_row() {
  local col1="$1"
  local col2="$2"
  local col3="$3"
  local col1_width=30
  local col2_width=14
  local col3_width=$(( TABLE_WIDTH - col1_width - col2_width - 7 ))

  if (( ${#col1} > col1_width )); then col1="${col1:0:$((col1_width-3))}..."; fi
  if (( ${#col2} > col2_width )); then col2="${col2:0:$((col2_width-3))}..."; fi
  if (( ${#col3} > col3_width )); then col3="${col3:0:$((col3_width-3))}..."; fi

  printf "│ %-${col1_width}s │ %-${col2_width}s│ %-${col3_width}s│\n" "$col1" "$col2" "$col3"
}

print_summary_line() {
  echo "$(printf '═%.0s' $(seq 1 $((TABLE_WIDTH+2))))"
}

# ============================================================================
# Input handling
# ============================================================================
if [[ -z "${OBJ_ID}" ]]; then
  read -r -p "Enter Entra Object ID (user/SP/group): " OBJ_ID
fi
[[ -z "$OBJ_ID" ]] && { echo "No Object ID provided."; exit 1; }

# Validate UUID format (with or without hyphens)
validate_uuid() {
  local uuid="$1"
  # Standard UUID format: 8-4-4-4-12 hex digits with hyphens
  local uuid_regex='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
  # Also accept 32 hex digits without hyphens
  local uuid_no_hyphen_regex='^[0-9a-fA-F]{32}$'

  if [[ "$uuid" =~ $uuid_regex ]] || [[ "$uuid" =~ $uuid_no_hyphen_regex ]]; then
    return 0
  else
    return 1
  fi
}

if ! validate_uuid "$OBJ_ID"; then
  echo "ERROR: Invalid Object ID format." >&2
  echo "Expected: UUID format (e.g., a1b2c3d4-e5f6-7890-abcd-ef1234567890)" >&2
  exit 1
fi

# ============================================================================
# Identity type detection (with improved error handling and timeouts)
# ============================================================================
detect_identity_type() {
  local obj_id="$1"
  local identity_type=""
  local display_name=""
  local result_json=""
  local error_output=""
  local exit_code=0
  local auth_error_detected=false
  local timeout_detected=false

  # Helper to check if error indicates auth/permission issues
  is_auth_error() {
    local err="$1"
    if [[ "$err" == *"Authorization"* ]] || \
       [[ "$err" == *"Forbidden"* ]] || \
       [[ "$err" == *"AccessDenied"* ]] || \
       [[ "$err" == *"Unauthorized"* ]] || \
       [[ "$err" == *"AADSTS"* ]] || \
       [[ "$err" == *"credentials"* ]] || \
       [[ "$err" == *"authentication"* ]]; then
      return 0
    fi
    return 1
  }

  # Helper to run az ad commands with timeout
  run_az_ad_with_timeout() {
    local error_file="$1"
    shift
    if [[ -n "$TIMEOUT_CMD" ]]; then
      $TIMEOUT_CMD "$AZ_CALL_TIMEOUT" az "$@" 2>"$error_file"
    else
      az "$@" 2>"$error_file"
    fi
  }

  # Try user first
  error_output=$(mktemp)
  result_json=$(run_az_ad_with_timeout "$error_output" ad user show --id "$obj_id") && exit_code=$? || exit_code=$?
  # Check for timeout (exit code 124)
  if [[ $exit_code -eq 124 ]]; then
    timeout_detected=true
  elif [[ $exit_code -eq 0 && -n "$result_json" ]]; then
    display_name=$(echo "$result_json" | jq -r '.displayName // empty')
    if [[ -n "$display_name" ]]; then
      rm -f "$error_output"
      echo "{\"type\": \"user\", \"displayName\": \"$display_name\", \"error\": null}"
      return 0
    fi
  elif is_auth_error "$(cat "$error_output" 2>/dev/null)"; then
    auth_error_detected=true
  fi

  # Try service principal
  result_json=$(run_az_ad_with_timeout "$error_output" ad sp show --id "$obj_id") && exit_code=$? || exit_code=$?
  if [[ $exit_code -eq 124 ]]; then
    timeout_detected=true
  elif [[ $exit_code -eq 0 && -n "$result_json" ]]; then
    display_name=$(echo "$result_json" | jq -r '.displayName // empty')
    if [[ -n "$display_name" ]]; then
      rm -f "$error_output"
      echo "{\"type\": \"servicePrincipal\", \"displayName\": \"$display_name\", \"error\": null}"
      return 0
    fi
  elif is_auth_error "$(cat "$error_output" 2>/dev/null)"; then
    auth_error_detected=true
  fi

  # Try group
  result_json=$(run_az_ad_with_timeout "$error_output" ad group show --group "$obj_id") && exit_code=$? || exit_code=$?
  if [[ $exit_code -eq 124 ]]; then
    timeout_detected=true
  elif [[ $exit_code -eq 0 && -n "$result_json" ]]; then
    display_name=$(echo "$result_json" | jq -r '.displayName // empty')
    if [[ -n "$display_name" ]]; then
      rm -f "$error_output"
      echo "{\"type\": \"group\", \"displayName\": \"$display_name\", \"error\": null}"
      return 0
    fi
  elif is_auth_error "$(cat "$error_output" 2>/dev/null)"; then
    auth_error_detected=true
  fi

  rm -f "$error_output"

  # Provide specific error feedback
  if [[ "$timeout_detected" == "true" ]]; then
    echo "{\"type\": \"unknown\", \"displayName\": \"\", \"error\": \"timeout\"}"
  elif [[ "$auth_error_detected" == "true" ]]; then
    echo "{\"type\": \"unknown\", \"displayName\": \"\", \"error\": \"access_denied\"}"
  else
    echo "{\"type\": \"unknown\", \"displayName\": \"\", \"error\": \"not_found\"}"
  fi
  return 1
}

# ============================================================================
# Get transitive group memberships
# ============================================================================
get_transitive_groups() {
  local obj_id="$1"
  local identity_type="$2"
  local url=""
  local groups_json=""

  case "$identity_type" in
    user)
      url="https://graph.microsoft.com/v1.0/users/$obj_id/transitiveMemberOf?\$select=id,displayName,@odata.type"
      ;;
    servicePrincipal)
      url="https://graph.microsoft.com/v1.0/servicePrincipals/$obj_id/transitiveMemberOf?\$select=id,displayName,@odata.type"
      ;;
    group)
      url="https://graph.microsoft.com/v1.0/groups/$obj_id/transitiveMemberOf?\$select=id,displayName,@odata.type"
      ;;
    *)
      echo "[]"
      return 0
      ;;
  esac

  groups_json=$(az_rest_with_timeout "$AZ_CALL_TIMEOUT" GET "$url" || echo '{"value":[]}')

  # Filter to only groups (exclude directory roles from this list)
  echo "$groups_json" | jq '[.value[] | select(.["@odata.type"] == "#microsoft.graph.group") | {id: .id, displayName: .displayName}]'
}

# ============================================================================
# Get Azure RBAC role assignments for an assignee
# ============================================================================
get_rbac_assignments() {
  local assignee_id="$1"
  local assignments_json=""

  assignments_json=$(az_with_timeout "$AZ_CALL_TIMEOUT_LONG" role assignment list --all \
    --assignee "$assignee_id" \
    --query "[].{RoleDefinitionName:roleDefinitionName, RoleDefinitionId:roleDefinitionId, Scope:scope}" \
    --output json || echo "[]")

  echo "$assignments_json"
}

# ============================================================================
# Resolve role definitions to full permission details
# ============================================================================
resolve_role_definitions() {
  local assignments_json="$1"
  local results=()

  # Extract unique roleDefinition GUID + name
  readarray -t ROLE_ROWS < <(
    echo "$assignments_json" | jq -r '
      map({
        id: (.RoleDefinitionId | split("/") | last),
        name: .RoleDefinitionName
      })
      | unique_by(.id)
      | .[]
      | [ .id, .name ] | @tsv
    ' 2>/dev/null || true
  )

  if (( ${#ROLE_ROWS[@]} == 0 )); then
    echo "[]"
    return 0
  fi

  for row in "${ROLE_ROWS[@]}"; do
    [[ -z "$row" ]] && continue
    IFS=$'\t' read -r ROLE_ID ROLE_NAME <<<"$row"

    ROLE_DEF_JSON=$(az_with_timeout "$AZ_CALL_TIMEOUT" role definition list --name "$ROLE_ID" --query "[0]" --output json || echo "null")
    if [[ -z "$ROLE_DEF_JSON" || "$ROLE_DEF_JSON" == "null" ]]; then
      continue
    fi

    ACTIONS=$(echo "$ROLE_DEF_JSON"        | jq '[.permissions[].actions]        | flatten | sort | unique')
    NOTACTIONS=$(echo "$ROLE_DEF_JSON"     | jq '[.permissions[].notActions]     | flatten | sort | unique')
    DATAACTIONS=$(echo "$ROLE_DEF_JSON"    | jq '[.permissions[].dataActions]    | flatten | sort | unique')
    NOTDATAACTIONS=$(echo "$ROLE_DEF_JSON" | jq '[.permissions[].notDataActions] | flatten | sort | unique')

    SCOPES=$(echo "$assignments_json" | jq --arg rid "$ROLE_ID" '
      [ .[] | select((.RoleDefinitionId | split("/") | last) == $rid) | .Scope ]
      | sort | unique
    ')

    ROLE_JSON=$(jq -n \
      --arg roleName "$ROLE_NAME" \
      --arg roleId "$ROLE_ID" \
      --argjson scopes "$SCOPES" \
      --argjson actions "$ACTIONS" \
      --argjson notActions "$NOTACTIONS" \
      --argjson dataActions "$DATAACTIONS" \
      --argjson notDataActions "$NOTDATAACTIONS" \
      '{
        roleName: $roleName,
        roleDefinitionId: $roleId,
        scopes: $scopes,
        permissions: {
          actions: $actions,
          notActions: $notActions,
          dataActions: $dataActions,
          notDataActions: $notDataActions
        }
      }')

    results+=("$ROLE_JSON")
  done

  if (( ${#results[@]} == 0 )); then
    echo "[]"
  else
    printf '%s\n' "${results[@]}" | jq -s '.'
  fi
}

# ============================================================================
# Get Entra ID directory role assignments for a principal
# ============================================================================
get_directory_roles() {
  local principal_id="$1"
  local inherited_from="${2:-}"
  local roles_json=""
  local results=()

  # Query directory role assignments
  roles_json=$(az_rest_with_timeout "$AZ_CALL_TIMEOUT" GET \
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=principalId eq '$principal_id'" \
    || echo '{"value":[]}')

  local assignments
  assignments=$(echo "$roles_json" | jq -r '.value[]? | [.roleDefinitionId, .id] | @tsv' 2>/dev/null || true)

  if [[ -z "$assignments" ]]; then
    echo "[]"
    return 0
  fi

  while IFS=$'\t' read -r role_def_id assignment_id; do
    [[ -z "$role_def_id" ]] && continue

    # Get role definition details
    local role_def
    role_def=$(az_rest_with_timeout "$AZ_CALL_TIMEOUT" GET \
      "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$role_def_id" \
      || echo '{}')

    local role_name
    role_name=$(echo "$role_def" | jq -r '.displayName // "Unknown"')

    local assignment_type="direct"
    local inherited_from_name="null"
    if [[ -n "$inherited_from" ]]; then
      assignment_type="inherited"
      inherited_from_name="\"$inherited_from\""
    fi

    local role_entry
    role_entry=$(jq -n \
      --arg roleName "$role_name" \
      --arg roleDefId "$role_def_id" \
      --arg assignmentType "$assignment_type" \
      --argjson inheritedFrom "$inherited_from_name" \
      '{
        roleName: $roleName,
        roleDefinitionId: $roleDefId,
        assignmentType: $assignmentType,
        inheritedFrom: $inheritedFrom
      }')

    results+=("$role_entry")
  done <<< "$assignments"

  if (( ${#results[@]} == 0 )); then
    echo "[]"
  else
    printf '%s\n' "${results[@]}" | jq -s '.'
  fi
}

# ============================================================================
# Get PIM eligible Entra ID directory roles
# ============================================================================
get_pim_entra_eligible() {
  local principal_id="$1"
  local results=()

  local eligible_json
  eligible_json=$(az_rest_with_timeout "$AZ_CALL_TIMEOUT" GET \
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?\$filter=principalId eq '$principal_id'" \
    || echo '{"value":[]}')

  local assignments
  assignments=$(echo "$eligible_json" | jq -r '.value[]? | [.roleDefinitionId, .startDateTime, .endDateTime] | @tsv' 2>/dev/null || true)

  if [[ -z "$assignments" ]]; then
    echo "[]"
    return 0
  fi

  while IFS=$'\t' read -r role_def_id start_dt end_dt; do
    [[ -z "$role_def_id" ]] && continue

    # Get role definition details
    local role_def
    role_def=$(az_rest_with_timeout "$AZ_CALL_TIMEOUT" GET \
      "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$role_def_id" \
      || echo '{}')

    local role_name
    role_name=$(echo "$role_def" | jq -r '.displayName // "Unknown"')

    local role_entry
    role_entry=$(jq -n \
      --arg roleName "$role_name" \
      --arg roleDefId "$role_def_id" \
      --arg startDt "${start_dt:-null}" \
      --arg endDt "${end_dt:-null}" \
      '{
        roleName: $roleName,
        roleDefinitionId: $roleDefId,
        status: "eligible",
        startDateTime: (if $startDt == "null" or $startDt == "" then null else $startDt end),
        endDateTime: (if $endDt == "null" or $endDt == "" then null else $endDt end)
      }')

    results+=("$role_entry")
  done <<< "$assignments"

  if (( ${#results[@]} == 0 )); then
    echo "[]"
  else
    printf '%s\n' "${results[@]}" | jq -s '.'
  fi
}

# ============================================================================
# Get PIM eligible Azure RBAC roles (with parallel subscription queries)
# ============================================================================

# Helper function to process PIM role assignments from JSON (rec 7: deduplicated)
_process_pim_assignments() {
  local eligible_json="$1"
  local output_file="$2"

  local assignments
  assignments=$(echo "$eligible_json" | jq -r '.value[]? | [.properties.roleDefinitionId, .properties.scope] | @tsv' 2>/dev/null || true)

  [[ -z "$assignments" ]] && return 0

  while IFS=$'\t' read -r role_def_id scope; do
    [[ -z "$role_def_id" ]] && continue

    local role_name
    role_name=$(echo "$role_def_id" | sed 's/.*\///')

    # Try to get friendly role name (with timeout)
    local role_def
    role_def=$(az_with_timeout "$AZ_CALL_TIMEOUT" role definition list --name "$role_name" --query "[0].roleName" -o tsv || echo "$role_name")

    jq -n \
      --arg roleName "$role_def" \
      --arg roleDefId "$role_def_id" \
      --arg scope "$scope" \
      '{
        roleName: $roleName,
        roleDefinitionId: $roleDefId,
        scope: $scope,
        status: "eligible"
      }' >> "$output_file"
  done <<< "$assignments"
}

# Helper function to query a single subscription (for parallel execution)
# Uses dynamically detected PIM_API_VERSION
_query_subscription_pim() {
  local sub_id="$1"
  local principal_id="$2"
  local output_file="$3"
  local api_version="$4"

  local eligible_json
  eligible_json=$(az_rest_with_timeout "$AZ_CALL_TIMEOUT" GET \
    "https://management.azure.com/subscriptions/$sub_id/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?\$filter=principalId eq '$principal_id'&api-version=$api_version" \
    || echo '{"value":[]}')

  _process_pim_assignments "$eligible_json" "$output_file"
}

get_pim_azure_rbac_eligible() {
  local principal_id="$1"
  local temp_dir
  temp_dir=$(mktemp -d)
  local combined_results="$temp_dir/combined.json"
  touch "$combined_results"

  # Get all subscriptions (with timeout)
  local subscriptions
  subscriptions=$(az_with_timeout "$AZ_CALL_TIMEOUT" account list --query "[].id" -o tsv || true)

  if [[ -z "$subscriptions" ]]; then
    # Try at provider level (management group or tenant-wide)
    local eligible_json
    eligible_json=$(az_rest_with_timeout "$AZ_CALL_TIMEOUT" GET \
      "https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?\$filter=principalId eq '$principal_id'&api-version=$PIM_API_VERSION" \
      || echo '{"value":[]}')

    _process_pim_assignments "$eligible_json" "$combined_results"
  else
    # Count subscriptions for parallel execution decision
    local sub_count
    sub_count=$(echo "$subscriptions" | wc -l)

    if (( sub_count <= 3 )); then
      # For few subscriptions, sequential is fine
      while read -r sub_id; do
        [[ -z "$sub_id" ]] && continue
        _query_subscription_pim "$sub_id" "$principal_id" "$combined_results" "$PIM_API_VERSION"
      done <<< "$subscriptions"
    else
      # For many subscriptions, use parallel execution with background jobs
      local max_parallel=5
      local job_count=0
      local pids=()

      while read -r sub_id; do
        [[ -z "$sub_id" ]] && continue

        # Create a sub-specific output file
        local sub_output="$temp_dir/sub_${sub_id}.json"

        # Run in background (pass API version)
        _query_subscription_pim "$sub_id" "$principal_id" "$sub_output" "$PIM_API_VERSION" &
        pids+=($!)
        ((job_count++))

        # Limit concurrent jobs
        if (( job_count >= max_parallel )); then
          # Wait for any job to finish
          wait -n 2>/dev/null || wait "${pids[0]}"
          # Remove completed PIDs (simplified: just decrement counter)
          ((job_count--))
        fi
      done <<< "$subscriptions"

      # Wait for all remaining jobs
      wait

      # Combine all subscription results
      for f in "$temp_dir"/sub_*.json; do
        [[ -f "$f" ]] && cat "$f" >> "$combined_results"
      done
    fi
  fi

  # Parse and deduplicate results
  if [[ -s "$combined_results" ]]; then
    jq -s 'unique_by(.roleDefinitionId + .scope)' "$combined_results"
  else
    echo "[]"
  fi

  # Cleanup
  rm -rf "$temp_dir"
}

# ============================================================================
# Table output functions
# ============================================================================
output_identity_table() {
  local obj_id="$1"
  local identity_type="$2"
  local display_name="$3"

  echo ""
  print_header_box "IDENTITY INFORMATION"
  print_kv_row "Object ID" "$obj_id"
  print_kv_row "Type" "$identity_type"
  print_kv_row "Display Name" "$display_name"
  print_section_footer
}

output_direct_rbac_table() {
  local rbac_json="$1"
  local count
  count=$(echo "$rbac_json" | jq 'length')

  echo ""
  print_section_header "DIRECT AZURE RBAC ROLES ($count)"

  if [[ "$count" -eq 0 ]]; then
    print_row "  No direct Azure RBAC roles found"
  else
    local first=true
    echo "$rbac_json" | jq -c '.[]' | while read -r role_entry; do
      local role_name scopes_json
      role_name=$(echo "$role_entry" | jq -r '.roleName')

      if [[ "$first" != "true" ]]; then
        print_table_separator
      fi
      first=false

      print_row "► $role_name"

      # Print each scope on its own line with wrapping
      echo "$role_entry" | jq -r '.scopes[]' | while read -r scope; do
        print_scope_row "  → " "$scope"
      done
    done
  fi
  print_section_footer
}

output_inherited_rbac_table() {
  local inherited_json="$1"
  local group_count
  group_count=$(echo "$inherited_json" | jq 'length')

  echo ""
  print_section_header "INHERITED AZURE RBAC ROLES ($group_count groups)"

  if [[ "$group_count" -eq 0 ]]; then
    print_row "  No inherited roles from groups"
  else
    local first_group=true
    echo "$inherited_json" | jq -c '.[]' | while read -r group_entry; do
      local group_name group_id
      group_name=$(echo "$group_entry" | jq -r '.groupName')
      group_id=$(echo "$group_entry" | jq -r '.groupId')

      if [[ "$first_group" != "true" ]]; then
        print_table_separator
      fi
      first_group=false

      print_row "► Group: $group_name"
      print_row "  ($group_id)"

      # Print each role with its scopes
      echo "$group_entry" | jq -c '.roles[]' | while read -r role_entry; do
        local role_name
        role_name=$(echo "$role_entry" | jq -r '.roleName')
        print_row "  ├─ $role_name"

        # Print each scope on its own line with wrapping
        echo "$role_entry" | jq -r '.scopes[]' | while read -r scope; do
          print_scope_row "  │    → " "$scope"
        done
      done
    done
  fi
  print_section_footer
}

output_entra_roles_table() {
  local entra_json="$1"
  local count
  count=$(echo "$entra_json" | jq 'length')

  echo ""
  print_section_header "ENTRA ID DIRECTORY ROLES ($count)"

  if [[ "$count" -eq 0 ]]; then
    print_row "  No Entra ID directory roles found"
  else
    print_three_col_header "Role" "Assignment" "Inherited From"
    echo "$entra_json" | jq -r '.[] | [.roleName, .assignmentType, (.inheritedFrom // "-")] | @tsv' | while IFS=$'\t' read -r role atype inherited; do
      print_three_col_row "$role" "$atype" "$inherited"
    done
  fi
  print_section_footer
}

output_pim_table() {
  local pim_entra="$1"
  local pim_rbac="$2"
  local entra_count rbac_count
  entra_count=$(echo "$pim_entra" | jq 'length')
  rbac_count=$(echo "$pim_rbac" | jq 'length')

  echo ""
  print_section_header "PIM ELIGIBLE ROLES"

  # Entra ID PIM
  print_row "ENTRA ID ROLES ($entra_count):"
  if [[ "$entra_count" -eq 0 ]]; then
    print_row "    No eligible Entra ID roles"
  else
    echo "$pim_entra" | jq -r '.[] | "    • \(.roleName) [\(.startDateTime // "N/A") → \(.endDateTime // "permanent")]"' | while read -r line; do
      print_row "$line"
    done
  fi

  print_row ""
  print_row "AZURE RBAC ROLES ($rbac_count):"
  if [[ "$rbac_count" -eq 0 ]]; then
    print_row "    No eligible Azure RBAC roles"
  else
    echo "$pim_rbac" | jq -c '.[]' | while read -r role_entry; do
      local role_name scope
      role_name=$(echo "$role_entry" | jq -r '.roleName')
      scope=$(echo "$role_entry" | jq -r '.scope')
      print_row "    • $role_name"
      print_scope_row "      → " "$scope"
    done
  fi

  print_section_footer
}

output_summary() {
  local direct_count="$1"
  local inherited_group_count="$2"
  local inherited_role_count="$3"
  local entra_count="$4"
  local entra_direct="$5"
  local entra_inherited="$6"
  local pim_entra_count="$7"
  local pim_rbac_count="$8"

  echo ""
  print_summary_line
  echo "                                    SUMMARY"
  print_summary_line
  printf "  %-28s : %s\n" "Direct RBAC Roles" "$direct_count"
  printf "  %-28s : %s (from %s groups)\n" "Inherited RBAC Roles" "$inherited_role_count" "$inherited_group_count"
  printf "  %-28s : %s (%s direct, %s inherited)\n" "Entra Directory Roles" "$entra_count" "$entra_direct" "$entra_inherited"
  printf "  %-28s : %s Entra + %s Azure RBAC\n" "PIM Eligible" "$pim_entra_count" "$pim_rbac_count"
  print_summary_line
  echo ""
}

# ============================================================================
# Main execution
# ============================================================================

log_progress "Detecting identity type for: $OBJ_ID"
IDENTITY_INFO=$(detect_identity_type "$OBJ_ID" || true)
IDENTITY_TYPE=$(echo "$IDENTITY_INFO" | jq -r '.type')
DISPLAY_NAME=$(echo "$IDENTITY_INFO" | jq -r '.displayName')
IDENTITY_ERROR=$(echo "$IDENTITY_INFO" | jq -r '.error // empty')

if [[ "$IDENTITY_TYPE" == "unknown" ]]; then
  if [[ "$IDENTITY_ERROR" == "timeout" ]]; then
    log_progress "WARN: Request timed out when querying identity. Azure may be slow or unreachable."
    log_progress "      You can increase timeout via AZ_CALL_TIMEOUT environment variable (current: ${AZ_CALL_TIMEOUT}s)."
    log_progress "      Proceeding with limited queries..."
  elif [[ "$IDENTITY_ERROR" == "access_denied" ]]; then
    log_progress "WARN: Access denied when querying identity. Check your permissions (Directory.Read.All required)."
    log_progress "      Proceeding with limited queries..."
  elif [[ "$IDENTITY_ERROR" == "not_found" ]]; then
    log_progress "WARN: Object ID not found as user, service principal, or group."
    log_progress "      The object may not exist or may be a different type. Proceeding with limited queries..."
  else
    log_progress "WARN: Could not determine identity type. Proceeding with limited queries."
  fi
else
  log_progress "Detected: $IDENTITY_TYPE - $DISPLAY_NAME"
fi

# Initialize result containers
GROUPS_JSON="[]"
INHERITED_RBAC_JSON="[]"
ENTRA_ROLES_JSON="[]"
PIM_ENTRA_JSON="[]"
PIM_RBAC_JSON="[]"

# ============================================================================
# Step 2: Group membership discovery
# ============================================================================
if [[ "$SKIP_GROUPS" == "false" && "$IDENTITY_TYPE" != "unknown" ]]; then
  log_progress "Discovering transitive group memberships..."
  GROUPS_JSON=$(get_transitive_groups "$OBJ_ID" "$IDENTITY_TYPE")
  GROUP_COUNT=$(echo "$GROUPS_JSON" | jq 'length')
  log_progress "Found $GROUP_COUNT group membership(s)"
else
  log_progress "Skipping group membership discovery (--skip-groups)"
fi

# ============================================================================
# Step 3: Direct Azure RBAC assignments
# ============================================================================
log_progress "Querying direct Azure RBAC assignments..."
DIRECT_ASSIGNMENTS=$(get_rbac_assignments "$OBJ_ID")
DIRECT_RBAC_JSON=$(resolve_role_definitions "$DIRECT_ASSIGNMENTS")
DIRECT_COUNT=$(echo "$DIRECT_RBAC_JSON" | jq 'length')
log_progress "Found $DIRECT_COUNT direct Azure RBAC role(s)"

# ============================================================================
# Step 4: Group-inherited Azure RBAC assignments
# ============================================================================
if [[ "$SKIP_GROUPS" == "false" ]]; then
  log_progress "Querying inherited Azure RBAC assignments..."
  INHERITED_RESULTS=()

  GROUP_IDS=$(echo "$GROUPS_JSON" | jq -r '.[] | [.id, .displayName] | @tsv' 2>/dev/null || true)

  if [[ -n "$GROUP_IDS" ]]; then
    while IFS=$'\t' read -r group_id group_name; do
      [[ -z "$group_id" ]] && continue

      log_progress "  Checking group: $group_name"
      GROUP_ASSIGNMENTS=$(get_rbac_assignments "$group_id")
      GROUP_ROLES=$(resolve_role_definitions "$GROUP_ASSIGNMENTS")

      ROLE_COUNT=$(echo "$GROUP_ROLES" | jq 'length')
      if [[ "$ROLE_COUNT" -gt 0 ]]; then
        log_progress "    Found $ROLE_COUNT role(s)"
        GROUP_ENTRY=$(jq -n \
          --arg groupId "$group_id" \
          --arg groupName "$group_name" \
          --argjson roles "$GROUP_ROLES" \
          '{
            groupId: $groupId,
            groupName: $groupName,
            roles: $roles
          }')
        INHERITED_RESULTS+=("$GROUP_ENTRY")
      fi
    done <<< "$GROUP_IDS"
  fi

  if (( ${#INHERITED_RESULTS[@]} == 0 )); then
    INHERITED_RBAC_JSON="[]"
  else
    INHERITED_RBAC_JSON=$(printf '%s\n' "${INHERITED_RESULTS[@]}" | jq -s '.')
  fi
else
  log_progress "Skipping group-inherited RBAC (--skip-groups)"
fi

# ============================================================================
# Step 5: Entra ID directory roles
# ============================================================================
if [[ "$SKIP_ENTRA" == "false" ]]; then
  log_progress "Querying Entra ID directory roles..."

  # Direct directory roles
  DIRECT_DIR_ROLES=$(get_directory_roles "$OBJ_ID" "")

  # Inherited via groups
  INHERITED_DIR_ROLES="[]"
  if [[ "$SKIP_GROUPS" == "false" ]]; then
    GROUP_IDS=$(echo "$GROUPS_JSON" | jq -r '.[] | [.id, .displayName] | @tsv' 2>/dev/null || true)

    if [[ -n "$GROUP_IDS" ]]; then
      INHERITED_ROLE_RESULTS=()
      while IFS=$'\t' read -r group_id group_name; do
        [[ -z "$group_id" ]] && continue

        log_progress "  Checking group: $group_name"
        GROUP_DIR_ROLES=$(get_directory_roles "$group_id" "$group_name")
        ROLE_COUNT=$(echo "$GROUP_DIR_ROLES" | jq 'length')

        if [[ "$ROLE_COUNT" -gt 0 ]]; then
          log_progress "    Found $ROLE_COUNT directory role(s)"
          INHERITED_ROLE_RESULTS+=("$GROUP_DIR_ROLES")
        fi
      done <<< "$GROUP_IDS"

      if (( ${#INHERITED_ROLE_RESULTS[@]} > 0 )); then
        INHERITED_DIR_ROLES=$(printf '%s\n' "${INHERITED_ROLE_RESULTS[@]}" | jq -s 'add')
      fi
    fi
  fi

  # Merge direct and inherited
  ENTRA_ROLES_JSON=$(jq -n \
    --argjson direct "$DIRECT_DIR_ROLES" \
    --argjson inherited "$INHERITED_DIR_ROLES" \
    '$direct + $inherited | unique_by(.roleName + .assignmentType + (.inheritedFrom // ""))')

  ENTRA_COUNT=$(echo "$ENTRA_ROLES_JSON" | jq 'length')
  log_progress "Found $ENTRA_COUNT Entra ID directory role(s)"
else
  log_progress "Skipping Entra ID directory roles (--skip-entra)"
fi

# ============================================================================
# Step 6: PIM eligible roles
# ============================================================================
if [[ "$SKIP_PIM" == "false" ]]; then
  # Initialize PIM API version (auto-detect if not set via environment)
  init_pim_api_version

  log_progress "Querying PIM eligible roles..."

  # PIM Entra ID roles
  PIM_ENTRA_JSON=$(get_pim_entra_eligible "$OBJ_ID")
  PIM_ENTRA_COUNT=$(echo "$PIM_ENTRA_JSON" | jq 'length')
  log_progress "  Found $PIM_ENTRA_COUNT eligible Entra ID role(s)"

  # PIM Azure RBAC roles
  PIM_RBAC_JSON=$(get_pim_azure_rbac_eligible "$OBJ_ID")
  PIM_RBAC_COUNT=$(echo "$PIM_RBAC_JSON" | jq 'length')
  log_progress "  Found $PIM_RBAC_COUNT eligible Azure RBAC role(s)"
else
  log_progress "Skipping PIM eligible roles (--skip-pim)"
fi

# ============================================================================
# Final output
# ============================================================================

if [[ "$OUTPUT_JSON" == "true" ]]; then
  # JSON output
  FINAL_JSON=$(jq -n \
    --arg objectId "$OBJ_ID" \
    --arg identityType "$IDENTITY_TYPE" \
    --arg displayName "$DISPLAY_NAME" \
    --argjson directAzureRBAC "$DIRECT_RBAC_JSON" \
    --argjson inheritedFromGroups "$INHERITED_RBAC_JSON" \
    --argjson entraDirectoryRoles "$ENTRA_ROLES_JSON" \
    --argjson pimEntraRoles "$PIM_ENTRA_JSON" \
    --argjson pimAzureRBAC "$PIM_RBAC_JSON" \
    '{
      identity: {
        objectId: $objectId,
        type: $identityType,
        displayName: $displayName
      },
      directAzureRBAC: $directAzureRBAC,
      inheritedFromGroups: $inheritedFromGroups,
      entraDirectoryRoles: $entraDirectoryRoles,
      pimEligible: {
        entraRoles: $pimEntraRoles,
        azureRBAC: $pimAzureRBAC
      }
    }')

  echo "$FINAL_JSON" | jq '.'
else
  # Table output
  output_identity_table "$OBJ_ID" "$IDENTITY_TYPE" "$DISPLAY_NAME"
  output_direct_rbac_table "$DIRECT_RBAC_JSON"

  if [[ "$SKIP_GROUPS" == "false" ]]; then
    output_inherited_rbac_table "$INHERITED_RBAC_JSON"
  fi

  if [[ "$SKIP_ENTRA" == "false" ]]; then
    output_entra_roles_table "$ENTRA_ROLES_JSON"
  fi

  if [[ "$SKIP_PIM" == "false" ]]; then
    output_pim_table "$PIM_ENTRA_JSON" "$PIM_RBAC_JSON"
  fi

  # Calculate summary stats
  DIRECT_COUNT=$(echo "$DIRECT_RBAC_JSON" | jq 'length')
  INHERITED_GROUP_COUNT=$(echo "$INHERITED_RBAC_JSON" | jq 'length')
  INHERITED_ROLE_COUNT=$(echo "$INHERITED_RBAC_JSON" | jq '[.[].roles | length] | add // 0')
  ENTRA_COUNT=$(echo "$ENTRA_ROLES_JSON" | jq 'length')
  ENTRA_DIRECT=$(echo "$ENTRA_ROLES_JSON" | jq '[.[] | select(.assignmentType == "direct")] | length')
  ENTRA_INHERITED=$(echo "$ENTRA_ROLES_JSON" | jq '[.[] | select(.assignmentType == "inherited")] | length')
  PIM_ENTRA_COUNT=$(echo "$PIM_ENTRA_JSON" | jq 'length')
  PIM_RBAC_COUNT=$(echo "$PIM_RBAC_JSON" | jq 'length')

  output_summary "$DIRECT_COUNT" "$INHERITED_GROUP_COUNT" "$INHERITED_ROLE_COUNT" \
                 "$ENTRA_COUNT" "$ENTRA_DIRECT" "$ENTRA_INHERITED" \
                 "$PIM_ENTRA_COUNT" "$PIM_RBAC_COUNT"
fi
