# Entra License Assignment Report

Generates a comprehensive Excel license report for one or more Entra ID tenants.
Covers user license assignments, device inventory, mailbox users, and license 
availability — with pivot tables for slicing by country, company, and license type.

Built for multi-tenant consulting scenarios where you need repeatable, structured 
license reporting across organisations.

---

## Overview

The report produces a single Excel workbook per tenant with the following sheets:

| Sheet | Contents |
|---|---|
| `UserData` | All users with full attributes and assigned licenses |
| `License` | Pivot table of license counts by country |
| `LicenseByCompany` | Pivot table of license counts by company |
| `LicenseActivated` | Available and consumed license counts |
| `MailboxUsers` | Users with active M365/Exchange mailbox licenses |
| `Devices` | Intune managed devices with compliance state and OS version |

---

## Prerequisites

- PowerShell 7+
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
- [ImportExcel module](https://github.com/dfinke/ImportExcel)
- A `licenses.ps1` file mapping SKU IDs to friendly names
- A `companies.ps1` file defining tenant configurations

## Required Graph Scopes

- `User.Read.All`
- `Directory.Read.All`
- `Organization.Read.All`
- `AuditLog.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementManagedDevices.Read.All`

---

## Configuration

Tenant configuration is defined in `companies.ps1` as a hashtable:

```powershell
$Global:tenants = @{
    'Contoso' = @{
        clientID   = '<app-client-id>'
        TenantID   = '<tenant-id>'
        extensions = @('extension_abc123_CustomAttribute')
    }
}
```

The `extensions` array is optional — add directory extension names here if you 
want custom attributes included in the report.

---

## Usage

```powershell
# Dot-source the script
. .\LicenseReport.ps1

# Generate report for a specific tenant
Get-LicenseReport -organization "Contoso"

# Generate reports for all configured tenants
Get-LicenseReport
```

---

## Output

Reports are saved automatically to:
`Documents\Reports\{OrgName}\{Year}\{Month}\{OrgName}LicenseUser-{Date}.xlsx`

If a synced SharePoint folder is detected, output is redirected there instead.

---

## Design Notes

- **SKU caching** — license SKU details are fetched once per unique SKU and 
  cached, avoiding repeated Graph calls across users with the same license.
- **Friendly license names** — SKU part numbers are translated to human-readable 
  names via `licenses.ps1`, making the report readable without a Microsoft 
  license decoder ring.
- **Multi-tenant support** — the script loops through all configured tenants 
  automatically, connecting and disconnecting between each one.
- **Directory extensions** — per-tenant custom extension attributes can be 
  included in the report output, making it adaptable to different governance 
  metadata setups.
- **Jens** — this script was lovingly dedicated to Jens, who inherited this 
  task without asking for it, deserving neither the responsibility nor the 
  comments, yet receiving both in equal measure. Jens, wherever you are: 
  the modules will install eventually. Probably.

---

## Author

**Sandra Saluti** — Identity & Governance Consultant at Epical
[LinkedIn](https://www.linkedin.com/in/sandra-saluti-6866a686/) ·
[Blog](https://agderinthe.cloud/author/sandra/)