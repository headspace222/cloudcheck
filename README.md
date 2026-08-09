# CloudCheck

**Inline compliance linting for Bicep, Terraform, and ARM templates. Directly in VS Code.**

CloudCheck flags security misconfigurations, naming violations, and missing governance controls as you write infrastructure code. No CLI setup. No pipeline required. Just open a `.bicep` or `.tf` file and save.

[![Marketplace](https://img.shields.io/badge/VS%20Code-Marketplace-007ACC)](https://marketplace.visualstudio.com/items?itemName=headspace222-dev.cloudcheck)
[![License](https://img.shields.io/badge/license-MIT-34D399)](LICENSE.txt)

---

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

---

## How it works

- Runs automatically on save. Configurable in settings.
- Flags issues as red and yellow squiggles on the exact problem line
- Shows all findings in the VS Code Problems panel (`Ctrl+Shift+M`).
- Status bar shows live issue count. Green when clean, red when critical issues exist.
- Every diagnostic includes the rule ID, description, and exact remediation.

---

## Supported files

- `.bicep` - Azure Bicep.
- `.tf` - Terraform HCL.
- `.json` - ARM templates, auto-detected by schema.

---

## Install

Search **CloudCheck** in the VS Code Extensions panel, or install from the command line:

```bash
code --install-extension headspace222-dev.cloudcheck
```

---

## Example findings

```
[CloudCheck STG-001] Public blob access must be disabled (CIS 3.1)
allowBlobPublicAccess: true exposes storage containers to the public internet.
Fix: properties: { allowBlobPublicAccess: false }

[CloudCheck NET-001] Wildcard inbound NSG rule detected (CIS 6.1)
An NSG rule allows all inbound traffic from any source. Critical exposure.
Fix: Replace sourceAddressPrefix: '*' with a specific CIDR or service tag.

[CloudCheck KV-002] Key Vault purge protection must be enabled (CIS 8.5)
Purge protection prevents permanent deletion during the retention period.
Fix: properties: { enablePurgeProtection: true }
```

---

## Settings

| Setting | Default | Description |
|---|---|---|
| `cloudcheck.enable` | `true` | Enable/disable the extension |
| `cloudcheck.lintOnSave` | `true` | Run checks on file save |
| `cloudcheck.lintOnType` | `false` | Run checks as you type |
| `cloudcheck.severity` | `all` | Minimum severity: `all`, `critical`, `high`, `medium` |

---

## Commands

- `CloudCheck: Run Compliance Check` - runs a check on the active file.
- `CloudCheck: Show Output Panel` - opens the CloudCheck output log.

---

## Compliance references

- [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [Microsoft Cloud Adoption Framework, Naming Conventions](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-naming)
- [Azure Security Baseline](https://learn.microsoft.com/en-us/security/benchmark/azure/)

---

## About

Built by [Jane Ologhadien](https://github.com/headspace222), cloud and infrastructure engineer.

Part of the [Cloud Engineering Toolkit](https://github.com/headspace222/cloud-engineering-toolkit), a free multi-cloud reference for Azure, AWS, and GCP engineers.

---

## Contributing

Found a missing rule or a false positive? [Open an issue](https://github.com/headspace222/cloudcheck/issues). Contributions are welcome.

---

*If CloudCheck has saved you time, a quick [review on the Marketplace](https://marketplace.visualstudio.com/items?itemName=headspace222-dev.cloudcheck&ssr=false#review-details) helps other engineers find it.*
