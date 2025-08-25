Scripts that I came up with during Azure security assessments:

# **iknowyourrole.sh**
## Overview
`iknowyourrole.sh` - small script for Azure environments that lets you quickly see what roles and permissions a specific Entra (Azure AD) user, group, or service principal actually has.

Workflow:
1. You provide the **Object ID** of the assignee (user / group / service principal).
2. The script queries Azure for all role assignments on that identity.
3. It extracts each unique role definition (by GUID), along with the scope where it is applied.
4. For each role definition, it pulls the **effective permissions**:
  - `actions`
  - `notActions`
  - `dataActions`
  - `notDataActions`

5. Finally, it outputs a structured JSON report showing every role, its scopes, and its permission sets.

Handy for pentesting, security reviews, or simply auditing which custom roles have been assigned and what they can actually do.


## Requirements
```
Azure CLI
jq
```


## Usage
Run it with an Entra Object ID:
```bash
./iknowyourrole.sh 508ae4eb-e9f9-4735-9f78-f098d0110e52
```

Or, run without arguments and it will prompt you interactively:
```bash
./iknowyourrole.sh
Enter Entra Object ID (user/SP/group): <paste objectId here>
```

### 3. Example Output
The script will:
- Show raw role assignments for the identity
- List the unique roles found
- Query each role definition
- Print a final JSON object like:

```json
[
  {
    "roleName": "Custom-AppService-Role",
    "roleDefinitionId": "489d4efe-aca9-f5cd-2dd6-fda55304fa93",
    "scopes": [
      "/subscriptions/.../resourceGroups/..."
    ],
    "permissions": {
      "actions": [
        "Microsoft.Web/sites/*/read",
        "Microsoft.Web/sites/*/write"
      ],
      "notActions": [],
      "dataActions": [],
      "notDataActions": []
    }
  }
]
```
