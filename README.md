# Azure Security Assessment Scripts

A collection of scripts for Azure/Entra ID security testing and assessments.

> **Disclaimer:** These tools are for authorized security testing only. Ensure you have explicit permission before testing any tenant.

---

## Scripts

### iknowyourrole.sh

Enumerates Azure RBAC role assignments and their effective permissions for a given identity.

**What it does:**
- Takes an Entra Object ID (user, group, or service principal)
- Lists all role assignments for that identity
- Extracts permissions (actions, notActions, dataActions, notDataActions) for each role
- Outputs a structured JSON report

**Requirements:** Azure CLI, jq

**Usage:**
```bash
./iknowyourrole.sh <Object_ID>
# or interactively:
./iknowyourrole.sh
```

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

🚧 *Work in progress* - Python version of the MFA bypass script.

---

## Author
@fhd342gs
