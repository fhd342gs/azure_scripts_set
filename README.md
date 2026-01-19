# Azure Security Assessment Scripts

A collection of scripts for Azure/Entra ID security testing and assessments.

> **Disclaimer:** These tools are for authorized security testing only. Ensure you have explicit permission before testing any tenant.

---

## Scripts

### azure-roles-digger.sh

Comprehensive role and permission discovery tool for Azure environments. Given an Entra Object ID (user, service principal, or group), this script discovers **ALL** effective permissions including inherited roles that are often missed by basic queries.

#### What It Discovers

| Category | Description |
|----------|-------------|
| **Direct Azure RBAC** | Role assignments directly on the identity |
| **Inherited Azure RBAC** | Roles inherited via group memberships (transitive) |
| **Entra ID Directory Roles** | Global Admin, User Admin, etc. (direct + inherited) |
| **PIM Eligible Roles** | Roles that can be activated via Privileged Identity Management |

#### Features

- **Automatic identity type detection** - Determines if Object ID is user, service principal, or group
- **Transitive group discovery** - Uses Microsoft Graph API to find ALL nested group memberships
- **Full permission extraction** - Gets actions, notActions, dataActions, notDataActions for each role
- **Beautiful table output** - Human-readable formatted tables (default)
- **JSON output** - Machine-readable format for scripting and automation
- **Selective discovery** - Skip specific checks with flags for faster execution
- **Parallel subscription queries** - Faster PIM RBAC discovery across multiple subscriptions
- **Auto-detect PIM API version** - Automatically uses the latest stable Azure PIM API version
- **Timeout protection** - Configurable timeouts prevent script hanging on slow/unresponsive APIs
- **Input validation** - UUID format validation prevents invalid API calls

#### Requirements

- **Azure CLI** (`az`) - authenticated with appropriate permissions
- **jq** - JSON processor
- **Bash 3.2+** (4.0+ recommended for best performance)
- **timeout** (optional, from coreutils) - enables timeout protection

#### Required Permissions

| Permission | Purpose |
|------------|---------|
| Reader on Azure subscriptions | Query RBAC role assignments |
| Directory.Read.All | Graph API group membership queries |
| RoleManagement.Read.Directory | Entra ID directory role queries |
| Privileged Role Reader | PIM eligible role queries |

#### Usage

```bash
# Interactive mode - prompts for Object ID
./azure-roles-digger.sh

# Direct with Object ID
./azure-roles-digger.sh a1b2c3d4-e5f6-7890-abcd-ef1234567890

# JSON output for scripting
./azure-roles-digger.sh --json a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Skip PIM and Entra checks (faster, Azure RBAC only)
./azure-roles-digger.sh --skip-pim --skip-entra a1b2c3d4-e5f6-7890-abcd-ef1234567890

# Quiet mode with JSON (ideal for piping)
./azure-roles-digger.sh --quiet --json $OBJECT_ID | jq '.directAzureRBAC'

# Only direct RBAC roles (skip all inheritance checks)
./azure-roles-digger.sh --skip-groups --skip-entra --skip-pim $OBJECT_ID
```

#### Options

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON instead of tables |
| `--skip-groups` | Skip group membership and inherited role discovery |
| `--skip-entra` | Skip Entra ID directory role discovery |
| `--skip-pim` | Skip PIM eligible role discovery |
| `--quiet` | Suppress progress messages (only show final output) |
| `--help`, `-h` | Show help message |

#### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AZ_CALL_TIMEOUT` | 30 | Timeout in seconds for standard API calls |
| `AZ_CALL_TIMEOUT_LONG` | 60 | Timeout for long operations (role assignment lists) |
| `PIM_API_VERSION` | auto-detect | Override the PIM API version (e.g., `2020-10-01`) |

**Examples with environment variables:**
```bash
# Increase timeout for slow networks
AZ_CALL_TIMEOUT=60 ./azure-roles-digger.sh $OBJECT_ID

# Force specific PIM API version
PIM_API_VERSION=2022-04-01-preview ./azure-roles-digger.sh $OBJECT_ID
```

#### Example Output (Table Mode)

```
╔══════════════════════════════════════════════════════════════════════════════════════════╗
║                                   IDENTITY INFORMATION                                    ║
╚══════════════════════════════════════════════════════════════════════════════════════════╝
│  Object ID       : a1b2c3d4-e5f6-7890-abcd-ef1234567890                                  │
│  Type            : user                                                                   │
│  Display Name    : John Doe                                                               │
└──────────────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                              DIRECT AZURE RBAC ROLES (3)                                 │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│ ► Key Vault Reader                                                                       │
│   → /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/prod-rg/providers │
│     /Microsoft.KeyVault/vaults/prod-vault                                                │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│ ► Contributor                                                                            │
│   → /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/dev-rg            │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│ ► Reader                                                                                 │
│   → /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94                                  │
└──────────────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                          INHERITED AZURE RBAC ROLES (1 groups)                           │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│ ► Group: Cloud-Admins                                                                    │
│   (abc123-def456-7890-abcd-ef1234567890)                                                 │
│   ├─ Owner                                                                               │
│   │    → /subscriptions/xxx-xxx-xxx                                                      │
│   ├─ Key Vault Administrator                                                             │
│   │    → /subscriptions/xxx-xxx/resourceGroups/keyvault-rg/providers/Microsoft.KeyVault  │
│         /vaults/admin-vault                                                              │
└──────────────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                             ENTRA ID DIRECTORY ROLES (3)                                 │
├────────────────────────────────┬───────────────┬─────────────────────────────────────────┤
│ Role                           │ Assignment    │ Inherited From                          │
├────────────────────────────────┼───────────────┼─────────────────────────────────────────┤
│ Global Reader                  │ direct        │ -                                       │
│ User Administrator             │ inherited     │ Cloud-Admins                            │
│ Application Administrator      │ inherited     │ Cloud-Admins                            │
└────────────────────────────────┴───────────────┴─────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                                  PIM ELIGIBLE ROLES                                      │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│ ENTRA ID ROLES (1):                                                                      │
│     • Global Administrator [2024-01-01 → 2025-01-01]                                     │
│                                                                                          │
│ AZURE RBAC ROLES (1):                                                                    │
│     • Owner → /subscriptions/xxx-xxx                                                     │
└──────────────────────────────────────────────────────────────────────────────────────────┘

════════════════════════════════════════════════════════════════════════════════════════════
                                         SUMMARY
════════════════════════════════════════════════════════════════════════════════════════════
  Direct RBAC Roles            : 2
  Inherited RBAC Roles         : 2 (from 1 groups)
  Entra Directory Roles        : 3 (1 direct, 2 inherited)
  PIM Eligible                 : 1 Entra + 1 Azure RBAC
════════════════════════════════════════════════════════════════════════════════════════════
```

#### JSON Output Structure

```json
{
  "identity": {
    "objectId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "type": "user",
    "displayName": "John Doe"
  },
  "directAzureRBAC": [
    {
      "roleName": "Contributor",
      "roleDefinitionId": "b24988ac-6180-42a0-ab88-20f7382dd24c",
      "scopes": ["/subscriptions/xxx/resourceGroups/prod-rg"],
      "permissions": {
        "actions": ["*"],
        "notActions": ["..."],
        "dataActions": [],
        "notDataActions": []
      }
    }
  ],
  "inheritedFromGroups": [
    {
      "groupId": "abc123-def456",
      "groupName": "Cloud-Admins",
      "roles": [...]
    }
  ],
  "entraDirectoryRoles": [
    {
      "roleName": "Global Reader",
      "roleDefinitionId": "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
      "assignmentType": "direct",
      "inheritedFrom": null
    }
  ],
  "pimEligible": {
    "entraRoles": [
      {
        "roleName": "Global Administrator",
        "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
        "status": "eligible",
        "startDateTime": "2024-01-01T00:00:00Z",
        "endDateTime": "2025-01-01T00:00:00Z"
      }
    ],
    "azureRBAC": [
      {
        "roleName": "Owner",
        "roleDefinitionId": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        "scope": "/subscriptions/xxx-xxx",
        "status": "eligible"
      }
    ]
  }
}
```

#### Use Cases

| Scenario | Command |
|----------|---------|
| Full security audit of a user | `./azure-roles-digger.sh $USER_OID` |
| Quick RBAC-only check | `./azure-roles-digger.sh --skip-entra --skip-pim $OID` |
| Export to file for reporting | `./azure-roles-digger.sh --json --quiet $OID > audit.json` |
| Check service principal permissions | `./azure-roles-digger.sh $SP_OID` |
| Audit a security group's effective access | `./azure-roles-digger.sh $GROUP_OID` |

---

### UA_MFA_bypass.ps1

Tests whether Conditional Access or MFA policies can be bypassed using legacy/non-browser client User-Agent spoofing via ROPC (Resource Owner Password Credential) flow.

Organizations often exclude legacy clients, IoT devices, and meeting room systems from MFA enforcement - this script tests for such gaps.

**Features:**
- Multiple target resources (ARM, Graph, KeyVault, Storage, DevOps, etc.)
- 35+ User-Agent profiles across categories:
  - Gaming consoles (PlayStation, Xbox)
  - Meeting room devices (Teams Room, Surface Hub) - *high success rate*
  - Legacy Outlook (2010/2013) - *commonly excluded*
  - Printers, embedded systems, healthcare devices
- Multiple client app impersonation options
- Token decode and validation

**Requirements:** PowerShell 5.1+

**Usage:**
```powershell
.\UA_MFA_bypass.ps1 -Resource Graph -UserAgent TeamsRoom -Verbose
.\UA_MFA_bypass.ps1 -Resource KeyVault -UserAgent Outlook2013
```

**After successful bypass:**
```powershell
# Token stored in $MFApwn
$MFApwn.access_token     # Use with API calls
$MFApwn.refresh_token    # For token renewal
```

---

### UA_MFA_bypass.py

*Work in progress* - Python version of the MFA bypass script.

---

## Author
@fhd342gs
