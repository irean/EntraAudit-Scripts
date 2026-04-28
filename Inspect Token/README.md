# Inspect Token

Decodes and inspects the current Microsoft Graph access token from your active 
session. Useful for troubleshooting access issues, verifying claims, confirming 
scopes, and understanding exactly what your token contains.

No token input required — the function extracts the token directly from the 
active Microsoft Graph session.

---

## Usage

```powershell
# Dot-source the script
. .\inspecttoken.ps1

# Connect to Microsoft Graph first
Connect-MgGraph -Scopes "User.Read.All"

# Inspect the current session token
Inspect-Token

# Inspect with verbose output (shows Base64 encoding steps)
Inspect-Token -Verbose
```

---

## Output

Returns a PSObject containing the decoded JWT payload, including:

| Claim | Description |
|---|---|
| `oid` | Object ID of the authenticated identity |
| `upn` | User Principal Name |
| `scp` | Delegated scopes granted |
| `roles` | Application roles granted |
| `tid` | Tenant ID |
| `aud` | Audience (resource the token is for) |
| `exp` | Token expiry timestamp |
| `iss` | Token issuer |
| `appid` | Application ID used to obtain the token |

The decoded header is also printed to the console, showing the signing algorithm 
and key ID.

---

## Design Notes

- **No token input needed** — the function extracts the Bearer token directly 
  from the most recent Graph request, so there is nothing to copy and paste.
- **RFC 7519 compliant** — validates that the token is a properly structured JWT 
  before attempting to decode it.
- **Works with access and ID tokens** — refresh tokens are not decodable by 
  design and will return an error.
- **Base64 padding handled automatically** — JWT tokens use URL-safe Base64 
  without padding, which the function corrects before decoding.

---

## Prerequisites

- PowerShell 7+
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
- An active Microsoft Graph session (`Connect-MgGraph`)

---

## Author

**Sandra Saluti** — Identity & Governance Consultant at Epical
[LinkedIn](https://www.linkedin.com/in/sandra-saluti-6866a686/) ·
[Blog](https://agderinthe.cloud/author/sandra/)