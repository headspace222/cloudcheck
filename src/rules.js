'use strict';

/**
 * CloudCheck Rules Engine
 * 38 checks across: Naming, Tags, Storage, Key Vault,
 * Networking, IAM, Observability, Encryption, Compute, Kubernetes, IaC Quality
 *
 * Each rule.check(text, format) returns:
 *   null  = not applicable to this template
 *   true  = passed
 *   false = failed (raise diagnostic)
 */

const RULES = [
  /* NAMING */
  {
    id: 'NAM-001', cat: 'Naming', sev: 'MEDIUM',
    name: 'Storage account name should use st prefix (CAF)',
    desc: 'CAF convention: storage account names use st prefix, no hyphens, lowercase only.',
    fix: 'Rename to: st<workload><env><region><instance>  e.g. stpaymentsprod001',
    check(t) {
      if (!/storageAccount|storage_account/i.test(t)) return null;
      const blocks = t.match(/Microsoft\.Storage\/storageAccounts[\s\S]{0,400}/gi) || [];
      for (const block of blocks) {
        const m = block.match(/name\s*[:=]\s*['"]([^'"]+)['"]/i);
        if (m && !m[1].startsWith('st') && !m[1].includes('param') &&
            !m[1].includes('var') && !m[1].includes('{')) return false;
      }
      return true;
    }
  },
  {
    id: 'NAM-002', cat: 'Naming', sev: 'MEDIUM',
    name: 'Key Vault name should use kv- prefix (CAF)',
    desc: 'CAF convention: Key Vault names use the kv- prefix.',
    fix: 'Rename to: kv-<workload>-<env>-<region>-<instance>',
    check(t) {
      if (!/KeyVault\/vaults|key_vault/i.test(t)) return null;
      const m = t.match(/Microsoft\.KeyVault\/vaults[\s\S]{0,300}/i);
      if (!m) return null;
      const nm = m[0].match(/name\s*[:=]\s*['"]([^'"]+)['"]/i);
      if (nm && !nm[1].startsWith('kv') && !nm[1].includes('param') && !nm[1].includes('{')) return false;
      return true;
    }
  },
  {
    id: 'NAM-003', cat: 'Naming', sev: 'LOW',
    name: 'Resource group name should use rg- prefix (CAF)',
    desc: 'CAF convention: resource group names use the rg- prefix.',
    fix: 'Rename to: rg-<workload>-<env>-<region>-<instance>',
    check(t) {
      if (!/resourceGroups|resource_group/i.test(t)) return null;
      const matches = t.match(/resourceGroupName\s*[:=]\s*['"]([^'"]+)['"]/gi) || [];
      for (const m of matches) {
        const nm = m.match(/['"]([^'"]+)['"]\s*$/);
        if (nm && !nm[1].startsWith('rg-') && !nm[1].includes('param') && !nm[1].includes('{')) return false;
      }
      return true;
    }
  },
  {
    id: 'NAM-004', cat: 'Naming', sev: 'LOW',
    name: 'NSG name should use nsg- prefix (CAF)',
    desc: 'CAF convention: Network Security Groups use the nsg- prefix.',
    fix: 'Rename to: nsg-<subnet>-<env>',
    check(t) {
      if (!/networkSecurityGroups|network_security_group/i.test(t)) return null;
      const m = t.match(/networkSecurityGroups[\s\S]{0,200}/i);
      if (!m) return null;
      const nm = m[0].match(/name\s*[:=]\s*['"]([^'"]+)['"]/i);
      if (nm && !nm[1].startsWith('nsg-') && !nm[1].includes('param') && !nm[1].includes('{')) return false;
      return true;
    }
  },

  /* TAGS */
  {
    id: 'TAG-001', cat: 'Tags', sev: 'HIGH',
    name: 'Environment tag missing',
    desc: 'All resources should declare an Environment or env tag for governance and cost allocation.',
    fix: "tags: { Environment: 'prod' }  or  tags = { env = \"prod\" }",
    check(t) {
      if (!/(tags|tag)\s*[:={]/i.test(t)) return false;
      return /\b(env|environment|Environment)\b/i.test(t);
    }
  },
  {
    id: 'TAG-002', cat: 'Tags', sev: 'HIGH',
    name: 'Owner tag missing',
    desc: 'An Owner tag identifies who is accountable for the resource.',
    fix: "tags: { Owner: 'platform-team@example.com' }",
    check(t) {
      if (!/(tags|tag)\s*[:={]/i.test(t)) return false;
      return /\b(owner|Owner)\b/i.test(t);
    }
  },
  {
    id: 'TAG-003', cat: 'Tags', sev: 'MEDIUM',
    name: 'CostCentre tag missing',
    desc: 'A CostCentre tag is required for chargeback reporting in regulated environments.',
    fix: "tags: { CostCentre: 'CC-1234' }",
    check(t) {
      return /(cost.?cent(re|er)|costcentre|cost_centre)/i.test(t);
    }
  },
  {
    id: 'TAG-004', cat: 'Tags', sev: 'LOW',
    name: 'ManagedBy tag recommended',
    desc: 'A ManagedBy tag (e.g. Terraform, Bicep) identifies IaC-managed resources.',
    fix: "tags: { ManagedBy: 'Bicep' }",
    check(t) {
      return /(managed.?by|managedby|managed_by)/i.test(t);
    }
  },

  /* STORAGE */
  {
    id: 'STG-001', cat: 'Storage', sev: 'CRITICAL',
    name: 'Public blob access must be disabled (CIS 3.1)',
    desc: 'allowBlobPublicAccess: true exposes storage containers to the public internet.',
    fix: 'properties: { allowBlobPublicAccess: false }',
    check(t) {
      if (!/storageAccount|storage_account|aws_s3_bucket|google_storage_bucket/i.test(t)) return null;
      if (/allowBlobPublicAccess\s*:\s*false/i.test(t)) return true;
      if (/allowBlobPublicAccess\s*:\s*true/i.test(t)) return false;
      if (/acl\s*=\s*['"]private['"]/i.test(t)) return true;
      if (/acl\s*=\s*['"]public/i.test(t)) return false;
      if (/Microsoft\.Storage\/storageAccounts/i.test(t)) return false;
      return null;
    }
  },
  {
    id: 'STG-002', cat: 'Storage', sev: 'CRITICAL',
    name: 'HTTPS-only traffic must be enforced (CIS 3.2)',
    desc: 'supportsHttpsTrafficOnly must be true to prevent unencrypted HTTP access.',
    fix: 'properties: { supportsHttpsTrafficOnly: true }',
    check(t) {
      if (!/storageAccount|storage_account/i.test(t)) return null;
      if (/supportsHttpsTrafficOnly\s*:\s*true/i.test(t)) return true;
      if (/supportsHttpsTrafficOnly\s*:\s*false/i.test(t)) return false;
      if (/Microsoft\.Storage\/storageAccounts/i.test(t)) return false;
      return null;
    }
  },
  {
    id: 'STG-003', cat: 'Storage', sev: 'HIGH',
    name: 'Minimum TLS version must be TLS 1.2 (CIS 3.3)',
    desc: 'TLS 1.0 and 1.1 are deprecated with known vulnerabilities.',
    fix: "properties: { minimumTlsVersion: 'TLS1_2' }",
    check(t) {
      if (!/storageAccount|storage_account/i.test(t)) return null;
      if (/TLS1_2|TLS1_3/i.test(t)) return true;
      if (/TLS1_0|TLS1_1/i.test(t)) return false;
      if (/Microsoft\.Storage\/storageAccounts/i.test(t)) return false;
      return null;
    }
  },
  {
    id: 'STG-004', cat: 'Storage', sev: 'HIGH',
    name: "Storage network default action must be Deny (CIS 3.7)",
    desc: "Default network action Allow means storage is publicly routable.",
    fix: "networkAcls: { defaultAction: 'Deny', bypass: 'AzureServices' }",
    check(t) {
      if (!/storageAccount|storage_account/i.test(t)) return null;
      if (/defaultAction\s*:\s*['"]Deny['"]/i.test(t)) return true;
      if (/defaultAction\s*:\s*['"]Allow['"]/i.test(t)) return false;
      return null;
    }
  },

  /* KEY VAULT */
  {
    id: 'KV-001', cat: 'Key Vault', sev: 'HIGH',
    name: 'Key Vault soft delete must be enabled (CIS 8.4)',
    desc: 'Soft delete prevents accidental or malicious permanent deletion of secrets.',
    fix: 'properties: { enableSoftDelete: true, softDeleteRetentionInDays: 90 }',
    check(t) {
      if (!/KeyVault\/vaults|key_vault/i.test(t)) return null;
      if (/enableSoftDelete\s*:\s*true/i.test(t)) return true;
      if (/enableSoftDelete\s*:\s*false/i.test(t)) return false;
      return null;
    }
  },
  {
    id: 'KV-002', cat: 'Key Vault', sev: 'HIGH',
    name: 'Key Vault purge protection must be enabled (CIS 8.5)',
    desc: 'Purge protection prevents permanent deletion during the retention period.',
    fix: 'properties: { enablePurgeProtection: true }',
    check(t) {
      if (!/KeyVault\/vaults|key_vault/i.test(t)) return null;
      if (/enablePurgeProtection\s*:\s*true/i.test(t)) return true;
      if (/enablePurgeProtection\s*:\s*false/i.test(t)) return false;
      return null;
    }
  },
  {
    id: 'KV-003', cat: 'Key Vault', sev: 'HIGH',
    name: 'Key Vault should use RBAC authorisation (CIS 8.1)',
    desc: 'RBAC mode is preferred over legacy access policies.',
    fix: 'properties: { enableRbacAuthorization: true }',
    check(t) {
      if (!/KeyVault\/vaults/i.test(t)) return null;
      if (/enableRbacAuthorization\s*:\s*true/i.test(t)) return true;
      if (/enableRbacAuthorization\s*:\s*false/i.test(t)) return false;
      return null;
    }
  },
  {
    id: 'KV-004', cat: 'Key Vault', sev: 'MEDIUM',
    name: 'Key Vault network access should be restricted',
    desc: "Key Vault default network action should be Deny to prevent public access.",
    fix: "networkAcls: { defaultAction: 'Deny', bypass: 'AzureServices' }",
    check(t) {
      if (!/KeyVault\/vaults/i.test(t)) return null;
      if (/networkAcls[\s\S]{0,200}defaultAction\s*:\s*['"]Deny['"]/i.test(t)) return true;
      if (/networkAcls[\s\S]{0,200}defaultAction\s*:\s*['"]Allow['"]/i.test(t)) return false;
      return null;
    }
  },

  /* NETWORKING */
  {
    id: 'NET-001', cat: 'Networking', sev: 'CRITICAL',
    name: 'Wildcard inbound NSG rule detected (CIS 6.1)',
    desc: 'An NSG rule allows all inbound traffic from any source. Critical exposure.',
    fix: "Replace sourceAddressPrefix: '*' with a specific CIDR or service tag.",
    check(t) {
      if (!/networkSecurityGroup|securityRule|aws_security_group/i.test(t)) return null;
      if (/direction\s*:\s*['"]Inbound['"]/i.test(t) &&
          /sourceAddressPrefix\s*:\s*['"]\*['"]/i.test(t) &&
          /access\s*:\s*['"]Allow['"]/i.test(t)) return false;
      if (/ingress[\s\S]{0,200}cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\]/i.test(t)) return false;
      return true;
    }
  },
  {
    id: 'NET-002', cat: 'Networking', sev: 'HIGH',
    name: 'SSH port 22 open to internet (CIS 6.2)',
    desc: 'Port 22 accessible from 0.0.0.0/0. Use Azure Bastion or restrict to known IPs.',
    fix: 'Remove port 22 from public inbound rules. Use AzureBastionSubnet.',
    check(t) {
      if (!/securityRule|security_group/i.test(t)) return null;
      if (/(destinationPortRange|to_port)\s*['":\s=]+['"]?22['"]?/i.test(t) &&
          /(sourceAddressPrefix\s*:\s*['"]\*['"]|0\.0\.0\.0\/0)/i.test(t)) return false;
      return true;
    }
  },
  {
    id: 'NET-003', cat: 'Networking', sev: 'HIGH',
    name: 'RDP port 3389 open to internet (CIS 6.3)',
    desc: 'Port 3389 accessible from 0.0.0.0/0. Use Azure Bastion.',
    fix: 'Remove port 3389 from public inbound rules. Use Azure Bastion.',
    check(t) {
      if (!/securityRule|security_group/i.test(t)) return null;
      if (/(destinationPortRange|to_port)\s*['":\s=]+['"]?3389['"]?/i.test(t) &&
          /(sourceAddressPrefix\s*:\s*['"]\*['"]|0\.0\.0\.0\/0)/i.test(t)) return false;
      return true;
    }
  },
  {
    id: 'NET-004', cat: 'Networking', sev: 'MEDIUM',
    name: 'VM has public IP address attached',
    desc: 'VMs should not have public IPs unless they are explicitly load balancers or jump hosts.',
    fix: 'Remove publicIPAllocationMethod or set publicIPAddress to null.',
    check(t) {
      if (!/virtualMachines/i.test(t)) return null;
      if (/publicIPAllocationMethod\s*:\s*['"]Static['"]|publicIPAllocationMethod\s*:\s*['"]Dynamic['"]/i.test(t)) return false;
      return true;
    }
  },

  /* IAM */
  {
    id: 'IAM-001', cat: 'IAM', sev: 'CRITICAL',
    name: 'Owner role assigned at broad scope (CIS 1.15)',
    desc: 'Owner role grants full control including RBAC. Must not be assigned broadly.',
    fix: 'Replace Owner with Contributor or a custom role at a specific resource scope.',
    check(t) {
      if (!/roleAssignment|role_assignment/i.test(t)) return null;
      if (/roleDefinitionId[\s\S]{0,200}Owner/i.test(t) ||
          /role_definition_name\s*=\s*['"]Owner['"]/i.test(t)) return false;
      return true;
    }
  },
  {
    id: 'IAM-002', cat: 'IAM', sev: 'HIGH',
    name: 'Hardcoded credentials detected',
    desc: 'Passwords or secrets are hardcoded. Use Key Vault references instead.',
    fix: 'Replace with Key Vault secret reference or a @secure() parameter.',
    check(t) {
      if (/adminPassword\s*:\s*['"][^'"]{4,}['"]/i.test(t) ||
          /password\s*=\s*['"][^'"]{4,}['"]/i.test(t) ||
          /client_secret\s*=\s*['"][^'"]+['"]/i.test(t)) return false;
      return true;
    }
  },
  {
    id: 'IAM-003', cat: 'IAM', sev: 'HIGH',
    name: 'Managed Identity not configured',
    desc: 'Resources should use Managed Identity rather than service principal credentials.',
    fix: "identity: { type: 'SystemAssigned' }",
    check(t) {
      if (!/virtualMachines|managedClusters|functionApp|webApp/i.test(t)) return null;
      return /SystemAssigned|UserAssigned/i.test(t);
    }
  },
  {
    id: 'IAM-004', cat: 'IAM', sev: 'MEDIUM',
    name: 'principalType not specified on role assignment',
    desc: 'Missing principalType can allow privilege escalation via type confusion.',
    fix: "properties: { principalType: 'ServicePrincipal' }",
    check(t) {
      if (!/roleAssignment/i.test(t)) return null;
      return /principalType\s*:/i.test(t);
    }
  },

  /* OBSERVABILITY */
  {
    id: 'OBS-001', cat: 'Observability', sev: 'HIGH',
    name: 'Diagnostic settings not configured (CIS 5.x)',
    desc: 'Resources should route logs to Log Analytics for audit and alerting.',
    fix: 'Add a Microsoft.Insights/diagnosticSettings resource.',
    check(t) {
      return /diagnosticSettings|diagnostic_setting|cloudwatch_log_group/i.test(t);
    }
  },
  {
    id: 'OBS-002', cat: 'Observability', sev: 'MEDIUM',
    name: 'Log Analytics workspace not referenced',
    desc: 'A Log Analytics Workspace should be linked for centralised log collection.',
    fix: 'workspaceId: logAnalyticsWorkspace.id',
    check(t) {
      return /logAnalyticsWorkspace|log_analytics_workspace|workspace_id/i.test(t);
    }
  },
  {
    id: 'OBS-003', cat: 'Observability', sev: 'LOW',
    name: 'Log retention below 365 days (CIS 5.1.2)',
    desc: 'Retention policy must be at least 365 days for compliance.',
    fix: 'retentionPolicy: { days: 365, enabled: true }',
    check(t) {
      if (!/retentionPolicy|retention_days|retention_in_days/i.test(t)) return null;
      const m = t.match(/days\s*:\s*(\d+)/i) || t.match(/retention_in_days\s*=\s*(\d+)/i);
      if (m && parseInt(m[1]) < 365) return false;
      return true;
    }
  },

  /* ENCRYPTION */
  {
    id: 'ENC-001', cat: 'Encryption', sev: 'HIGH',
    name: 'Encryption at rest not explicitly enabled (CIS 7.x)',
    desc: 'Storage and database resources should explicitly enable encryption at rest.',
    fix: 'encryption: { services: { blob: { enabled: true }, file: { enabled: true } } }',
    check(t) {
      if (!/storageAccount|managedDisk|sqlDatabase/i.test(t)) return null;
      if (/encryption[\s\S]{0,200}enabled\s*:\s*false/i.test(t)) return false;
      return true;
    }
  },
  {
    id: 'ENC-002', cat: 'Encryption', sev: 'HIGH',
    name: 'Database TLS not enforced (CIS 4.3)',
    desc: 'Database connections must enforce TLS to protect data in transit.',
    fix: "sslEnforcement: 'Enabled'  or  require_secure_transport = true",
    check(t) {
      if (!/sql|postgres|mysql|database/i.test(t)) return null;
      if (/sslEnforcement\s*:\s*['"]Disabled['"]/i.test(t) ||
          /require_secure_transport\s*=\s*false/i.test(t)) return false;
      if (/sslEnforcement\s*:\s*['"]Enabled['"]/i.test(t)) return true;
      return null;
    }
  },

  /* KUBERNETES */
  {
    id: 'AKS-001', cat: 'Kubernetes', sev: 'HIGH',
    name: 'AKS RBAC must be enabled',
    desc: 'Kubernetes RBAC controls pod and API access. Must be enabled.',
    fix: 'properties: { enableRBAC: true }',
    check(t) {
      if (!/managedClusters|kubernetes_cluster/i.test(t)) return null;
      if (/enableRBAC\s*:\s*false/i.test(t) ||
          /role_based_access_control_enabled\s*=\s*false/i.test(t)) return false;
      if (/enableRBAC\s*:\s*true/i.test(t)) return true;
      return null;
    }
  },
  {
    id: 'AKS-002', cat: 'Kubernetes', sev: 'HIGH',
    name: 'AKS network policy not configured',
    desc: 'Network policy controls pod-to-pod traffic. Required for zero-trust K8s.',
    fix: "networkProfile: { networkPolicy: 'calico' }",
    check(t) {
      if (!/managedClusters|kubernetes_cluster/i.test(t)) return null;
      return /networkPolicy\s*['":\s=]+['"]?(calico|azure|cilium)/i.test(t);
    }
  },
  {
    id: 'AKS-003', cat: 'Kubernetes', sev: 'MEDIUM',
    name: 'AKS cluster autoscaler not enabled',
    desc: 'Autoscaler should be enabled to handle variable load without manual intervention.',
    fix: 'enableAutoScaling: true with minCount and maxCount defined.',
    check(t) {
      if (!/managedClusters|kubernetes_cluster/i.test(t)) return null;
      return /enableAutoScaling\s*:\s*true|enable_auto_scaling\s*=\s*true/i.test(t);
    }
  },

  /* IaC QUALITY */
  {
    id: 'IAC-001', cat: 'IaC Quality', sev: 'HIGH',
    name: 'Hardcoded secret in template',
    desc: 'Secrets must not appear in IaC templates. Use Key Vault or environment variables.',
    fix: 'Replace with a @secure() parameter or Key Vault secret reference.',
    check(t) {
      if (/password\s*[:=]\s*['"][^'"]{8,}['"]/i.test(t) ||
          /apikey\s*[:=]\s*['"][A-Za-z0-9+/]{16,}['"]/i.test(t)) return false;
      return true;
    }
  },
  {
    id: 'IAC-002', cat: 'IaC Quality', sev: 'MEDIUM',
    name: 'Bicep API version is outdated (pre-2021)',
    desc: 'Resource API versions should be 2021 or newer.',
    fix: 'Update resource API version to 2023-01-01 or latest stable.',
    check(t) {
      const matches = t.match(/@20(\d\d)-/g) || [];
      for (const m of matches) {
        const yr = parseInt(m.match(/20(\d\d)/)[1]);
        if (yr < 21) return false;
      }
      return true;
    }
  },
  {
    id: 'IAC-003', cat: 'IaC Quality', sev: 'LOW',
    name: 'No output values defined',
    desc: 'Modules should define outputs (IDs, URIs) for dependent resources.',
    fix: 'output storageId string = storageAccount.id',
    check(t) {
      return /^output\s+/im.test(t) || /output\s+['"]/im.test(t);
    }
  },
  {
    id: 'IAC-004', cat: 'IaC Quality', sev: 'LOW',
    name: 'Bicep parameters missing @description decorator',
    desc: 'All parameters should have @description() for documentation.',
    fix: "@description('The location for this resource')\nparam location string",
    check(t) {
      if (!/^param\s+\w+/im.test(t)) return null;
      if (/@description/i.test(t)) return true;
      if (/^param\s+\w+\s+\w+/im.test(t) && !/@description/i.test(t)) return false;
      return null;
    }
  },

  /* TERRAFORM */
  {
    id: 'TF-001', cat: 'Terraform', sev: 'HIGH',
    name: 'No remote state backend configured',
    desc: 'Terraform state must be stored remotely with locking. Local state is not production-safe.',
    fix: 'terraform { backend "azurerm" { ... } }',
    check(t, fmt) {
      if (fmt !== 'terraform') return null;
      return /backend\s+['"](azurerm|s3|gcs)['"]/i.test(t);
    }
  },
  {
    id: 'TF-002', cat: 'Terraform', sev: 'MEDIUM',
    name: 'Provider version not pinned',
    desc: 'Unpinned providers can cause unexpected breaking changes on terraform init.',
    fix: 'version = "~> 3.0" inside required_providers block.',
    check(t, fmt) {
      if (fmt !== 'terraform') return null;
      return /required_providers[\s\S]{0,400}version\s*=\s*["'~>=]/i.test(t);
    }
  },
  {
    id: 'TF-003', cat: 'Terraform', sev: 'LOW',
    name: 'required_version not set',
    desc: 'required_version ensures consistent Terraform CLI versions across the team.',
    fix: 'terraform { required_version = ">= 1.5.0" }',
    check(t, fmt) {
      if (fmt !== 'terraform') return null;
      return /required_version\s*=/i.test(t);
    }
  },

  /* BICEP */
  {
    id: 'BCP-001', cat: 'Bicep', sev: 'LOW',
    name: 'targetScope not declared',
    desc: 'Bicep files should declare targetScope for clarity and portability.',
    fix: "targetScope = 'subscription'",
    check(t, fmt) {
      if (fmt !== 'bicep') return null;
      if (!/^param\s+|^resource\s+/im.test(t)) return null;
      return /targetScope\s*=/i.test(t);
    }
  }
];

module.exports = { RULES };
