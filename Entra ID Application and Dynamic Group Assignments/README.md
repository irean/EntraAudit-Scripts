# Entra ID Application Role and Dynamic Group Assignments

Exports a combined report of application role assignments and dynamic group 
memberships for Entra ID users. Useful for access reviews, application governance, 
and understanding how users gain access to applications — directly or through 
dynamic group membership.

---

## Overview

This script produces a single Excel workbook with two sheets:

| Sheet | Contents |
|---|---|
| `ApplicationAssignments` | All app role assignments per user, including SSO type and SCIM provisioning status |
| `DynamicGroupAssignments` | All dynamic group memberships per user, including membership rules |

The script accepts either a targeted Excel list of users or runs against all 
member users in the tenant.

---

## Prerequisites

- PowerShell 7+
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
- [ImportExcel module](https://github.com/dfinke/ImportExcel)

## Required Graph Scopes

```powershell
Connect-MgGraph -Scopes "Organization.Read.All", "User.Read.All", `
    "GroupMember.Read.All", "Group.Read.All", "Application.Read.All"
```

---

## Usage

```powershell
.\Export-EntraID_AppRole_DynamicGroups.ps1
```

The script will:
1. Check and install required modules automatically
2. Prompt you to connect to Microsoft Graph
3. Ask whether you have an Excel list of target users
4. Prompt you to select an export folder
5. Collect app role assignments and dynamic group memberships
6. Export results to Excel

The output file is automatically named:
`OrganizationName_Application_Dynamicgroup_Assignments_YYYY-MM-DD.xlsx`

---

## User Input Options

**Option 1 — Excel file of target users**
Provide an Excel file with a column named `userPrincipalName`. The script 
will retrieve each user from Entra ID and scope the report to that list.

**Option 2 — All tenant users**
The script retrieves all member users from Entra ID and runs the full report 
across the entire tenant. Note: this can take a while on large tenants.

---

## What the Report Captures

**Application Assignments sheet**

| Column | Description |
|---|---|
| `UserPrincipalName` | User's UPN |
| `DisplayName` | User's display name |
| `resourceDisplayName` | Application name |
| `assignmentType` | Direct or group-based |
| `GroupDisplayName` | Group name if group-based |
| `SSO` | SSO type detected (SAML, OIDC, or False) |
| `SCIM` | Whether SCIM provisioning is active for the app |

**Dynamic Group Assignments sheet**

| Column | Description |
|---|---|
| `UserPrincipalName` | User's UPN |
| `GroupDisplayName` | Dynamic group name |
| `membershipRule` | The dynamic membership rule expression |
| `groupTypes` | Group type flags |
| `mailenabled` / `securityenabled` | Group properties |

---

## Design Notes

- **Service principal caching** — service principals are cached after the first 
  lookup to avoid redundant Graph calls across users assigned to the same app.
- **SSO detection** — the script infers SSO type from the service principal's 
  `preferredSingleSignOnMode` and redirect URIs, distinguishing between SAML, 
  OIDC, and non-SSO applications.
- **SCIM detection** — checks whether an active synchronization job exists on 
  the service principal, indicating SCIM provisioning is configured.
- **Dynamic groups only** — group membership is filtered to dynamic groups 
  exclusively, keeping the report focused on automatically assigned access.

---

## Author

**Sandra Saluti** — Identity & Governance Consultant at Epical
[LinkedIn](https://www.linkedin.com/in/sandra-saluti-6866a686/) ·
[Blog](https://agderinthe.cloud/author/sandra/)