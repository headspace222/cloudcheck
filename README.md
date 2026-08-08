# CloudCheck

Inline compliance linting for Bicep, Terraform, and ARM templates — directly in VS Code.

CloudCheck flags security misconfigurations, naming violations, and missing governance controls as you write infrastructure code, with no CLI setup, no pipeline required.

## What it checks

38 rules across 11 categories, mapped to CIS Azure Benchmark and CAF:

| Category | Rules | Examples |
|---|---|---|
| Naming | 4 | CAF prefixes for storage, Key Vault, NSG, resource groups |
| Tags | 4 | Environment, Owner, CostCentre, ManagedBy |
| Storage | 4 | Public access, HTTPS-only, TLS 1.2, network ACLs |
| Key Vault | 4 | Soft delete, purge protection, RBAC mode, network restriction |
| Networking | 4 | Wildcard NSG rules, SSH/RDP open to internet, public IPs |
| IAM | 4 | Owner role at broad scope, hardcoded credentials, managed identity |
| Observability | 3 | Diagnostic settings, Log Analytics, retention >= 365 days |
| Encryption | 2 | Encryption at rest, TLS on databases |
| Kubernetes | 3 | RBAC, network policy, autoscaler |
| IaC Quality | 4 | Hardcoded secrets, API versions, outputs, parameter descriptions |
| Terraform | 3 | Remote state, provider pinning, required_version |

## How it works

- Runs automatically on save (configurable)
- Flags issues as red/yellow squiggles in the editor
- Shows all findings in the VS Code Problems panel (`Ctrl+Shift+M`)
- Status bar shows live issue count
- Each diagnostic includes the rule ID, description, and exact remediation

## Supported files

- `.bicep` — Azure Bicep
- `.tf` — Terraform HCL
- `.json` — ARM templates (auto-detected by schema)

## Settings

| Setting | Default | Description |
|---|---|---|
| `cloudcheck.enable` | `true` | Enable/disable the extension |
| `cloudcheck.lintOnSave` | `true` | Run checks on file save |
| `cloudcheck.lintOnType` | `false` | Run checks as you type |
| `cloudcheck.severity` | `all` | Minimum severity: `all`, `critical`, `high`, `medium` |

## Commands

- `CloudCheck: Run Compliance Check` — manual run on active file
- `CloudCheck: Show Output Panel` — open the CloudCheck output log

## Example findings

```
[CloudCheck STG-001] Public blob access must be disabled (CIS 3.1)
allowBlobPublicAccess: true exposes storage containers to the public internet.
Fix: properties: { allowBlobPublicAccess: false }

[CloudCheck NET-001] Wildcard inbound NSG rule detected (CIS 6.1)
An NSG rule allows all inbound traffic from any source. Critical exposure.
Fix: Replace sourceAddressPrefix: '*' with a specific CIDR or service tag.
```

## Compliance references

- CIS Microsoft Azure Foundations Benchmark
- Microsoft Cloud Adoption Framework (CAF) naming conventions
- Azure Security Baseline

## About

Built by Jane Ologhadien. Part of the [Cloud Engineering Toolkit](https://github.com/YOUR_USERNAME/cloud-engineering-toolkit).
