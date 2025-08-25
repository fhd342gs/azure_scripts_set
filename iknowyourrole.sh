#!/usr/bin/env bash
set -euo pipefail

command -v az >/dev/null 2>&1 || { echo "Azure CLI (az) not found."; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq not found."; exit 1; }

OBJ_ID="${1-}"
if [[ -z "${OBJ_ID}" ]]; then
  read -r -p "Enter Entra Object ID (user/SP/group): " OBJ_ID
fi
[[ -z "$OBJ_ID" ]] && { echo "No Object ID provided."; exit 1; }

echo "== Step 1: Listing role assignments for assignee (objectId): $OBJ_ID"
ASSIGNMENTS_JSON="$(az role assignment list --all \
  --assignee "$OBJ_ID" \
  --query "[].{RoleDefinitionName:roleDefinitionName, RoleDefinitionId:roleDefinitionId, Scope:scope}" \
  --output json)"

echo "== Step 2: Raw output (assignments):"
echo "$ASSIGNMENTS_JSON" | jq '.'

# Extract unique roleDefinition GUID + name
readarray -t ROLE_ROWS < <(
  echo "$ASSIGNMENTS_JSON" | jq -r '
    map({
      id: (.RoleDefinitionId | split("/") | last),
      name: .RoleDefinitionName
    })
    | unique_by(.id)
    | .[]
    | [ .id, .name ] | @tsv
  '
)

if (( ${#ROLE_ROWS[@]} == 0 )); then
  echo "No roles found for this assignee."
  exit 0
fi

echo "== Step 3: Found ${#ROLE_ROWS[@]} unique role definition(s):"
for row in "${ROLE_ROWS[@]}"; do
  IFS=$'\t' read -r ROLE_ID ROLE_NAME <<<"$row"
  echo " - $ROLE_NAME  ($ROLE_ID)"
done

echo "== Step 4: Querying role definitions → permissions (actions/notActions/dataActions/notDataActions)..."
RESULTS=()

for row in "${ROLE_ROWS[@]}"; do
  IFS=$'\t' read -r ROLE_ID ROLE_NAME <<<"$row"

  ROLE_DEF_JSON="$(az role definition list --name "$ROLE_ID" --query "[0]" --output json || true)"
  if [[ -z "$ROLE_DEF_JSON" || "$ROLE_DEF_JSON" == "null" ]]; then
    echo "WARN: Could not resolve role definition for $ROLE_NAME ($ROLE_ID). Skipping."
    continue
  fi

  ACTIONS=$(echo "$ROLE_DEF_JSON"        | jq '[.permissions[].actions]        | flatten | sort | unique')
  NOTACTIONS=$(echo "$ROLE_DEF_JSON"     | jq '[.permissions[].notActions]     | flatten | sort | unique')
  DATAACTIONS=$(echo "$ROLE_DEF_JSON"    | jq '[.permissions[].dataActions]    | flatten | sort | unique')
  NOTDATAACTIONS=$(echo "$ROLE_DEF_JSON" | jq '[.permissions[].notDataActions] | flatten | sort | unique')

  SCOPES=$(echo "$ASSIGNMENTS_JSON" | jq --arg rid "$ROLE_ID" '
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

  RESULTS+=("$ROLE_JSON")
done

echo "== Aggregated role → permissions (+ scopes):"
printf '%s\n' "${RESULTS[@]}" | jq -s '.'
