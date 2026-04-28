# Entra Admin Role Report

Generates a comprehensive Excel report of all admin role assignments in Microsoft 
Entra ID and Azure, including active assignments, PIM eligible roles, and Azure 
subscription role assignments.

Built for governance and security reviews where you need a complete picture of 
who has privileged access — and when they last used it.

---

## Overview

This script produces a single Excel workbook with three sheets:

| Sheet | Contents |
|---|---|
| `Administrators` | All active directory role assignments, excluding PIM-activated roles |
| `Eligible Roles` | All PIM eligible role assignments, including group-based eligibility |
| `Azure Roles` | Role assignments across all Azure subscriptions |

For each user the report includes last sign-in datetime, account status, company 
name, password age, and creation date — giving you the context needed to identify 
stale or risky admin accounts at a glance.

---

## Prerequisites

- PowerShell 7+
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
- [Az PowerShell module](https://learn.microsoft.com/en-us/powershell/azure/install-az-ps)
- [ImportExcel module](https://github.com/dfinke/ImportExcel)
- A `$tenantID` variable set before running the script

## Required Permissions

| Scope | Purpose |
|---|---|
| `RoleManagement.Read.Directory` | Read directory role assignments |
| `RoleManagement.Read.All` | Read all role management data |
| `RoleEligibilitySchedule.Read.Directory` | Read PIM eligible role schedules |
| `User.Read.All` | Read user details including sign-in activity |
| `Group.Read.All` | Expand group-based role assignments |
| `Directory.Read.All` | Read directory data |
| `AuditLog.Read.All` | Read sign-in activity |
| `Organization.Read.All` | Read organisation display name |
| Az RBAC Reader | Read Azure subscription role assignments |

---

## Usage

```powershell
# Set your tenant ID before running
$tenantID = "<your-tenant-id>"

# Run the script
.\EntraAdminReport.ps1
```

The script will:
1. Install and import required modules automatically
2. Connect to both Microsoft Graph and Azure
3. Prompt you to select an export folder
4. Cache all users for performance
5. Collect active assignments, PIM eligible roles, and Azure role assignments
6. Export results to Excel

The output file is automatically named:
`OrganizationName-EntraIDAdminReport-YYYY-MM-DD.xlsx`

---

## Design Notes

- **User caching** — all users are pre-fetched and cached at startup to avoid 
  repeated Graph calls per role member, significantly improving performance on 
  large tenants.
- **PIM separation** — active PIM-activated roles are explicitly excluded from 
  the Administrators sheet and reported separately in Eligible Roles, avoiding 
  double-counting.
- **Group expansion** — group-based role assignments are expanded transitively, 
  so nested group members are included in the report.
- **Sign-in activity** — last sign-in datetime is included for every user, 
  making it easy to identify dormant admin accounts.

---

## Author

**Sandra Saluti** — Identity & Governance Consultant at Epical
[LinkedIn](https://www.linkedin.com/in/sandra-saluti-6866a686/) ·
[Blog](https://agderinthe.cloud/author/sandra/)