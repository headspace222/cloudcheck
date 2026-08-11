# CloudCheck Rule Reference

38 rules mapped to CIS Microsoft Azure Foundations Benchmark and Microsoft Cloud Adoption Framework naming conventions.

---

## Naming

| ID | Severity | Rule | CIS / CAF Reference |
|---|---|---|---|
| NAM-001 | MEDIUM | Storage account name should use st prefix | CAF naming |
| NAM-002 | MEDIUM | Key Vault name should use kv- prefix | CAF naming |
| NAM-003 | LOW | Resource group name should use rg- prefix | CAF naming |
| NAM-004 | LOW | NSG name should use nsg- prefix | CAF naming |

---

## Tags

| ID | Severity | Rule | Reference |
|---|---|---|---|
| TAG-001 | HIGH | Environment tag missing | Governance baseline |
| TAG-002 | HIGH | Owner tag missing | Governance baseline |
| TAG-003 | MEDIUM | CostCentre tag missing | Cost management |
| TAG-004 | LOW | ManagedBy tag recommended | IaC governance |

---

## Storage

| ID | Severity | Rule | CIS Reference |
|---|---|---|---|
| STG-001 | CRITICAL | Public blob access must be disabled | CIS 3.1 |
| STG-002 | CRITICAL | HTTPS-only traffic must be enforced | CIS 3.2 |
| STG-003 | HIGH | Minimum TLS version must be TLS 1.2 | CIS 3.3 |
| STG-004 | HIGH | Storage network default action must be Deny | CIS 3.7 |

---

## Key Vault

| ID | Severity | Rule | CIS Reference |
|---|---|---|---|
| KV-001 | HIGH | Key Vault soft delete must be enabled | CIS 8.4 |
| KV-002 | HIGH | Key Vault purge protection must be enabled | CIS 8.5 |
| KV-003 | HIGH | Key Vault should use RBAC authorisation | CIS 8.1 |
| KV-004 | MEDIUM | Key Vault network access should be restricted | CIS 8.x |

---

## Networking

| ID | Severity | Rule | CIS Reference |
|---|---|---|---|
| NET-001 | CRITICAL | Wildcard inbound NSG rule detected | CIS 6.1 |
| NET-002 | HIGH | SSH port 22 open to internet | CIS 6.2 |
| NET-003 | HIGH | RDP port 3389 open to internet | CIS 6.3 |
| NET-004 | MEDIUM | VM has public IP address attached | CIS 6.x |

---

## IAM

| ID | Severity | Rule | CIS Reference |
|---|---|---|---|
| IAM-001 | CRITICAL | Owner role assigned at broad scope | CIS 1.15 |
| IAM-002 | HIGH | Hardcoded credentials detected | Security baseline |
| IAM-003 | HIGH | Managed Identity not configured | Security baseline |
| IAM-004 | MEDIUM | principalType not specified on role assignment | Security baseline |

---

## Observability

| ID | Severity | Rule | CIS Reference |
|---|---|---|---|
| OBS-001 | HIGH | Diagnostic settings not configured | CIS 5.x |
| OBS-002 | MEDIUM | Log Analytics workspace not referenced | CIS 5.x |
| OBS-003 | LOW | Log retention below 365 days | CIS 5.1.2 |

---

## Encryption

| ID | Severity | Rule | CIS Reference |
|---|---|---|---|
| ENC-001 | HIGH | Encryption at rest not explicitly enabled | CIS 7.x |
| ENC-002 | HIGH | Database TLS not enforced | CIS 4.3 |

---

## Kubernetes

| ID | Severity | Rule | Reference |
|---|---|---|---|
| AKS-001 | HIGH | AKS RBAC must be enabled | AKS security baseline |
| AKS-002 | HIGH | AKS network policy not configured | AKS security baseline |
| AKS-003 | MEDIUM | AKS cluster autoscaler not enabled | AKS best practices |

---

## IaC Quality

| ID | Severity | Rule | Reference |
|---|---|---|---|
| IAC-001 | HIGH | Hardcoded secret in template | Security baseline |
| IAC-002 | MEDIUM | Bicep API version is outdated (pre-2022) | CAF best practices |
| IAC-003 | LOW | No output values defined | IaC quality |
| IAC-004 | LOW | Bicep parameters missing @description decorator | IaC quality |

---

## Terraform

| ID | Severity | Rule | Reference |
|---|---|---|---|
| TF-001 | HIGH | No remote state backend configured | Terraform best practices |
| TF-002 | MEDIUM | Provider version not pinned | Terraform best practices |
| TF-003 | LOW | required_version not set | Terraform best practices |

---

## Bicep

| ID | Severity | Rule | Reference |
|---|---|---|---|
| BCP-001 | LOW | targetScope not declared | Bicep best practices |
| BCP-002 | LOW | Subscription-scoped file missing targetScope declaration | Bicep best practices |

---

## Severity levels

| Level | Meaning |
|---|---|
| CRITICAL | Immediate security risk. Fix before deploying. |
| HIGH | Significant risk or compliance violation. Should be fixed. |
| MEDIUM | Best practice violation. Fix in the next iteration. |
| LOW | Quality or documentation improvement. Fix when convenient. |
