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
| `Entra Admin Role Report/` | Reports on admin role assignments across the tenant |
| `Entra ID Access Package Assignment Audit/` | Audits access package assignments in Entra ID Governance |
| `Entra ID Application and Dynamic Group Assignments/` | Exports application roles and dynamic group memberships |
| `Entra License Assignment Report/` | Reports on license assignments across users |
| `inspecttoken.ps1` | Decodes and inspects access tokens for troubleshooting and verification |

---

## Prerequisites

- PowerShell 7+
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
- Appropriate Entra ID permissions per script (documented in each script header)

---

## Design Philosophy

Good auditing is not about checking boxes — it is about knowing what questions 
to ask. These scripts are built around the principle that visibility comes before 
governance. You cannot govern what you cannot see.

A few principles baked in:
- **Report on what exists, not what should exist** — surface the reality of your 
  tenant before making changes
- **Token inspection matters** — understanding what is inside a token is fundamental 
  to troubleshooting access issues
- **License visibility drives cost and compliance** — knowing who has what license 
  assigned is the foundation of both

---

## Contributing

Found a bug or have an improvement? Issues and PRs are welcome.

---

## Author

**Sandra Saluti** — Identity & Governance Consultant at Epical  
[LinkedIn](https://www.linkedin.com/in/sandra-saluti-6866a686/) · 
[Blog](https://agderinthe.cloud/author/sandra/)