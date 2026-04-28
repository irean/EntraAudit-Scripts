# EntraAudit-Scripts

PowerShell scripts for auditing your Entra ID environment — admin role assignments,
access package assignments, application and dynamic group exports, license reporting,
and token inspection.

Built from real-world consulting work. Use these when you need visibility into
what is actually happening in your tenant.

Related blog posts at [agderinthe.cloud](https://agderinthe.cloud/author/sandra/)

---

## Contents

| Script / Folder | What it does |
|---|---|
| `Entra Admin Role Report/` | Comprehensive report of all active and PIM eligible role assignments across Entra ID and Azure, including last sign-in activity and account status |
| `Entra ID Access Package Assignment Audit/` | Interactive wizard that compares a user population against an Access Package and exports a detailed Excel report with assignment status, summaries, and pivot charts |
| `Entra ID Application and Dynamic Group Assignments/` | Exports app role assignments per user including SSO type and SCIM provisioning status, alongside dynamic group memberships and membership rules |
| `Entra License Assignment Report/` | Multi-tenant license report covering user license assignments, device inventory, mailbox users, and license availability — with pivot tables by country and company |
| `inspecttoken.ps1` | Decodes and inspects the current Microsoft Graph session token — no copy-paste required |

---

## Prerequisites

- PowerShell 7+
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
- [ImportExcel module](https://github.com/dfinke/ImportExcel)
- [Az PowerShell module](https://learn.microsoft.com/en-us/powershell/azure/install-az-ps) — required for Admin Role Report only

## Required Graph Scopes

Scope requirements vary per script. Each script folder contains its own README
with the specific scopes required. At a minimum across all scripts:

- `User.Read.All`
- `Directory.Read.All`
- `Organization.Read.All`
- `AuditLog.Read.All`
- `RoleManagement.Read.All`
- `EntitlementManagement.Read.All`
- `Application.Read.All`
- `DeviceManagementManagedDevices.Read.All`

---

## Design Philosophy

Good auditing is not about checking boxes — it is about knowing what questions
to ask. These scripts are built around the principle that visibility comes before
governance. You cannot govern what you cannot see.

A few principles baked in across all scripts:
- **Report on what exists, not what should exist** — surface the reality of your
  tenant before making changes
- **Cache aggressively** — users, SKUs, and service principals are cached to
  avoid hammering the Graph API on large tenants
- **Export with context** — raw data alone is not a report. Every script produces
  structured Excel output with summaries, pivot tables, and filtering built in
- **Token inspection matters** — understanding what is inside a token is
  fundamental to troubleshooting access issues

---

## Contributing

Found a bug or have an improvement? Issues and PRs are welcome.

---

## Author

**Sandra Saluti** — Identity & Governance Consultant at Epical
[LinkedIn](https://www.linkedin.com/in/sandra-saluti-6866a686/) ·
[Blog](https://agderinthe.cloud/author/sandra/)