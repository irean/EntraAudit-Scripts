# Entra ID Access Package Assignment Audit

Audit and compare Entra ID user populations against Access Package assignments.
Built for governance teams who need visibility into who should have access — and who doesn't.

---

## Overview

This script provides an interactive audit wizard that:
1. Retrieves users from Entra ID using filters, group membership, or CSV import
2. Compares them against a specified Access Package
3. Exports a detailed Excel report with assignment status, summaries, and a pivot chart

---

## Functions

| Function | Description |
|---|---|
| `Start-UserAccessPackageAudit` | Main entry point — interactive wizard to run the full audit |
| `Get-UsersDynamic` | Retrieves users by filter, group membership, or manual input |
| `Get-AccessPackageAssignmentsTargets` | Gets all delivered assignments for a specific Access Package |
| `Compare-UsersToAccessPackageAssignments` | Compares a user list to Access Package assignments |
| `Compare-UsersToAccessPackageAssignmentsWithProgress` | Same as above with real-time progress feedback |
| `Export-AccessPackageReportToExcel` | Exports audit results to a formatted Excel workbook |
| `Select-FolderPath` | Opens a folder picker dialog for export path selection |

---

## Prerequisites

- PowerShell 7+
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
- [ImportExcel module](https://github.com/dfinke/ImportExcel)

## Required Graph Scopes

- `User.Read.All`
- `Organization.Read.All`
- `Group.Read.All`
- `EntitlementManagement.Read.All`

---

## Quick Start

```powershell
# Dot-source the script
. .\Report-EntraIDAccessPackageAssignment.ps1

# Run the interactive audit wizard
Start-UserAccessPackageAudit
```

The wizard will guide you through:
- Selecting how to retrieve users (filter / group / CSV)
- Entering the Access Package ObjectId
- Selecting an export folder

---

## Output

The exported Excel workbook contains:

| Sheet | Contents |
|---|---|
| `DetailedReport` | All users with full attributes and assignment status |
| `Summary` | Counts per Access Package policy, with pivot table and 3D pie chart |
| `UserNotAssigned` | Filtered list of users not assigned to the Access Package |

The filename is automatically generated:
`OrganizationName-AccessPackageName-YYYY-MM-DD.xlsx`

---

## Example

```powershell
# Run individual functions if needed
$users = Get-UsersDynamic -Country "Denmark" -CompanyName "Contoso ApS"
$results = Compare-UsersToAccessPackageAssignmentsWithProgress `
    -AccessPackageId "b3a77f84-6a3d-44b1-9f50-d32c17346a31" `
    -UserList $users

$results | Where-Object { -not $_.Assigned }
```

---

## Author

**Sandra Saluti** — Identity & Governance Consultant at Epical
[LinkedIn](https://www.linkedin.com/in/sandra-saluti-6866a686/) ·
[Blog](https://agderinthe.cloud/author/sandra/)