'use strict';

/**
 * CloudCheck Smart Rules Engine
 * 
 * Uses the AST parser (parser.js) instead of regex.
 * Each rule receives a ParseResult and returns:
 *   null            = not applicable
 *   true            = passed
 *   false           = failed (line 0)
 *   { passed, line, detail }  = failed with specific location
 */

const { parse } = require('./parser');

const SMART_RULES = [

  /* ── NAMING ─────────────────────────────────────────── */
  {
    id: 'NAM-001', cat: 'Naming', sev: 'MEDIUM',
    name: 'Storage account name should use st prefix (CAF)',
    desc: 'CAF convention: storage account names use the st prefix, no hyphens, lowercase only.',
    fix: 'Rename to: st<workload><env><region><instance>  e.g. stpaymentsprod001',
    check(result) {
      const resources = result.resourcesOfType(/Storage\/storageAccounts|azurerm_storage_account|google_storage_bucket/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const name = typeof r.name === 'string' ? r.name : null;
        if (!name) continue;
        // Skip param/var references and interpolations
        if (name.startsWith('__ref:') || name.includes('{')) continue;
        if (!name.startsWith('st') && !name.startsWith('sa') && !name.startsWith('storage')) {
          return { passed: false, line: r.line, detail: `Resource name '${name}' does not use st prefix` };
        }
      }
      return true;
    }
  },
  {
    id: 'NAM-002', cat: 'Naming', sev: 'MEDIUM',
    name: 'Key Vault name should use kv- prefix (CAF)',
    desc: 'CAF convention: Key Vault names use the kv- prefix.',
    fix: 'Rename to: kv-<workload>-<env>-<region>-<instance>',
    check(result) {
      const resources = result.resourcesOfType(/KeyVault\/vaults|azurerm_key_vault/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const name = typeof r.name === 'string' ? r.name : null;
        if (!name || name.startsWith('__ref:')) continue;
        if (!name.startsWith('kv-') && !name.startsWith('kv')) {
          return { passed: false, line: r.line, detail: `Key Vault '${name}' does not use kv- prefix` };
        }
      }
      return true;
    }
  },
  {
    id: 'NAM-003', cat: 'Naming', sev: 'LOW',
    name: 'Resource group name should use rg- prefix (CAF)',
    desc: 'CAF convention: resource group names use the rg- prefix.',
    fix: 'Rename to: rg-<workload>-<env>-<region>-<instance>',
    check(result) {
      const resources = result.resourcesOfType(/Resources\/resourceGroups|azurerm_resource_group/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const name = typeof r.name === 'string' ? r.name : null;
        if (!name || name.startsWith('__ref:')) continue;
        if (!name.startsWith('rg-')) {
          return { passed: false, line: r.line, detail: `Resource group '${name}' does not use rg- prefix` };
        }
      }
      return true;
    }
  },
  {
    id: 'NAM-004', cat: 'Naming', sev: 'LOW',
    name: 'NSG name should use nsg- prefix (CAF)',
    desc: 'CAF convention: Network Security Groups use the nsg- prefix.',
    fix: 'Rename to: nsg-<subnet>-<env>',
    check(result) {
      const resources = result.resourcesOfType(/networkSecurityGroups|azurerm_network_security_group/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const name = typeof r.name === 'string' ? r.name : null;
        if (!name || name.startsWith('__ref:')) continue;
        if (!name.startsWith('nsg-')) {
          return { passed: false, line: r.line, detail: `NSG '${name}' does not use nsg- prefix` };
        }
      }
      return true;
    }
  },

  /* ── TAGS ───────────────────────────────────────────── */
  {
    id: 'TAG-001', cat: 'Tags', sev: 'HIGH',
    name: 'Environment tag missing',
    desc: 'All resources should declare an Environment or env tag for governance and cost allocation.',
    fix: "tags: { Environment: 'prod' }  or  tags = { env = \"prod\" }",
    check(result) {
      const has = result.hasTag('env') || result.hasTag('environment') || result.hasTag('Environment');
      if (!has && result.resources().length > 0) return false;
      return has ? true : null;
    }
  },
  {
    id: 'TAG-002', cat: 'Tags', sev: 'HIGH',
    name: 'Owner tag missing',
    desc: 'An Owner tag identifies who is accountable for the resource.',
    fix: "tags: { Owner: 'platform-team@example.com' }",
    check(result) {
      if (!result.resources().length) return null;
      return result.hasTag('owner') || result.hasTag('Owner') ? true : false;
    }
  },
  {
    id: 'TAG-003', cat: 'Tags', sev: 'MEDIUM',
    name: 'CostCentre tag missing',
    desc: 'A CostCentre tag is required for chargeback reporting in regulated environments.',
    fix: "tags: { CostCentre: 'CC-1234' }",
    check(result) {
      if (!result.resources().length) return null;
      return result.hasTag('costcentre') || result.hasTag('cost_centre') || result.hasTag('CostCentre') ? true : false;
    }
  },
  {
    id: 'TAG-004', cat: 'Tags', sev: 'LOW',
    name: 'ManagedBy tag recommended',
    desc: 'A ManagedBy tag (e.g. Terraform, Bicep) identifies IaC-managed resources.',
    fix: "tags: { ManagedBy: 'Bicep' }",
    check(result) {
      if (!result.resources().length) return null;
      return result.hasTag('managedby') || result.hasTag('ManagedBy') || result.hasTag('managed_by') ? true : false;
    }
  },

  /* ── STORAGE ────────────────────────────────────────── */
  {
    id: 'STG-001', cat: 'Storage', sev: 'CRITICAL',
    name: 'Public blob access must be disabled (CIS 3.1)',
    desc: 'allowBlobPublicAccess: true exposes storage containers to the public internet.',
    fix: 'properties: { allowBlobPublicAccess: false }',
    check(result) {
      const resources = result.resourcesOfType(/Storage\/storageAccounts|azurerm_storage_account/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const val = result.prop(r, 'allowBlobPublicAccess') ??
                    result.prop(r, 'properties.allowBlobPublicAccess') ??
                    result.prop(r, 'allow_blob_public_access');
        if (val === true) return { passed: false, line: r.line, detail: 'allowBlobPublicAccess is true' };
        if (val === false) return true;
        // If not set explicitly in Azure, default is true (insecure)
        if (r.resourceType && /Storage\/storageAccounts/i.test(r.resourceType) && val === undefined) {
          return { passed: false, line: r.line, detail: 'allowBlobPublicAccess not set (defaults to true)' };
        }
      }
      return true;
    }
  },
  {
    id: 'STG-002', cat: 'Storage', sev: 'CRITICAL',
    name: 'HTTPS-only traffic must be enforced (CIS 3.2)',
    desc: 'supportsHttpsTrafficOnly must be true to prevent unencrypted HTTP access.',
    fix: 'properties: { supportsHttpsTrafficOnly: true }',
    check(result) {
      const resources = result.resourcesOfType(/Storage\/storageAccounts|azurerm_storage_account/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const val = result.prop(r, 'supportsHttpsTrafficOnly') ??
                    result.prop(r, 'properties.supportsHttpsTrafficOnly') ??
                    result.prop(r, 'enable_https_traffic_only');
        if (val === false) return { passed: false, line: r.line, detail: 'supportsHttpsTrafficOnly is false' };
        if (val === undefined && /Storage\/storageAccounts/i.test(r.resourceType || '')) {
          return { passed: false, line: r.line, detail: 'supportsHttpsTrafficOnly not set (must be explicit)' };
        }
      }
      return true;
    }
  },
  {
    id: 'STG-003', cat: 'Storage', sev: 'HIGH',
    name: 'Minimum TLS version must be TLS 1.2 (CIS 3.3)',
    desc: 'TLS 1.0 and 1.1 are deprecated with known vulnerabilities.',
    fix: "properties: { minimumTlsVersion: 'TLS1_2' }",
    check(result) {
      const resources = result.resourcesOfType(/Storage\/storageAccounts|azurerm_storage_account/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const val = result.prop(r, 'minimumTlsVersion') ??
                    result.prop(r, 'properties.minimumTlsVersion') ??
                    result.prop(r, 'min_tls_version');
        if (val === 'TLS1_0' || val === 'TLS1_1') {
          return { passed: false, line: r.line, detail: `minimumTlsVersion is ${val} — must be TLS1_2` };
        }
        if (val === undefined && /Storage\/storageAccounts/i.test(r.resourceType || '')) {
          return { passed: false, line: r.line, detail: 'minimumTlsVersion not set (defaults to TLS1_0)' };
        }
      }
      return true;
    }
  },
  {
    id: 'STG-004', cat: 'Storage', sev: 'HIGH',
    name: "Storage network default action must be Deny (CIS 3.7)",
    desc: "Default network action Allow means storage is publicly routable.",
    fix: "networkAcls: { defaultAction: 'Deny', bypass: 'AzureServices' }",
    check(result) {
      const resources = result.resourcesOfType(/Storage\/storageAccounts|azurerm_storage_account/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const val = result.prop(r, 'networkAcls.defaultAction') ??
                    result.prop(r, 'properties.networkAcls.defaultAction') ??
                    result.prop(r, 'defaultAction') ??
                    result.prop(r, 'network_rules.default_action');
        if (val === 'Allow') return { passed: false, line: r.line, detail: "networkAcls.defaultAction is 'Allow' — should be 'Deny'" };
        if (val === 'Deny') return true;
      }
      return null;
    }
  },

  /* ── KEY VAULT ──────────────────────────────────────── */
  {
    id: 'KV-001', cat: 'Key Vault', sev: 'HIGH',
    name: 'Key Vault soft delete must be enabled (CIS 8.4)',
    desc: 'Soft delete prevents accidental or malicious permanent deletion of secrets.',
    fix: 'properties: { enableSoftDelete: true, softDeleteRetentionInDays: 90 }',
    check(result) {
      const resources = result.resourcesOfType(/KeyVault\/vaults|azurerm_key_vault/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const val = result.prop(r, 'enableSoftDelete') ??
                    result.prop(r, 'properties.enableSoftDelete') ??
                    result.prop(r, 'soft_delete_enabled') ??
                    result.prop(r, 'soft_delete_retention_days');
        if (val === false) return { passed: false, line: r.line, detail: 'enableSoftDelete is false' };
      }
      return true;
    }
  },
  {
    id: 'KV-002', cat: 'Key Vault', sev: 'HIGH',
    name: 'Key Vault purge protection must be enabled (CIS 8.5)',
    desc: 'Purge protection prevents permanent deletion during the retention period.',
    fix: 'properties: { enablePurgeProtection: true }',
    check(result) {
      const resources = result.resourcesOfType(/KeyVault\/vaults|azurerm_key_vault/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const val = result.prop(r, 'enablePurgeProtection') ??
                    result.prop(r, 'properties.enablePurgeProtection') ??
                    result.prop(r, 'purge_protection_enabled');
        if (val === false) return { passed: false, line: r.line, detail: 'enablePurgeProtection is false' };
      }
      return true;
    }
  },
  {
    id: 'KV-003', cat: 'Key Vault', sev: 'HIGH',
    name: 'Key Vault should use RBAC authorisation (CIS 8.1)',
    desc: 'RBAC mode is preferred over legacy access policies.',
    fix: 'properties: { enableRbacAuthorization: true }',
    check(result) {
      const resources = result.resourcesOfType(/KeyVault\/vaults|azurerm_key_vault/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const val = result.prop(r, 'enableRbacAuthorization') ??
                    result.prop(r, 'properties.enableRbacAuthorization');
        if (val === false) return { passed: false, line: r.line, detail: 'enableRbacAuthorization is false — RBAC should be used over access policies' };
        if (val === true) return true;
      }
      return null;
    }
  },
  {
    id: 'KV-004', cat: 'Key Vault', sev: 'MEDIUM',
    name: 'Key Vault network access should be restricted',
    desc: "Key Vault default network action should be Deny to prevent public access.",
    fix: "networkAcls: { defaultAction: 'Deny', bypass: 'AzureServices' }",
    check(result) {
      const resources = result.resourcesOfType(/KeyVault\/vaults|azurerm_key_vault/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const val = result.prop(r, 'networkAcls.defaultAction') ??
                    result.prop(r, 'properties.networkAcls.defaultAction') ??
                    result.prop(r, 'defaultAction');
        if (val === 'Allow') return { passed: false, line: r.line, detail: "Key Vault network defaultAction is 'Allow'" };
        if (val === 'Deny') return true;
      }
      return null;
    }
  },

  /* ── NETWORKING ─────────────────────────────────────── */
  {
    id: 'NET-001', cat: 'Networking', sev: 'CRITICAL',
    name: 'Wildcard inbound NSG rule detected (CIS 6.1)',
    desc: 'An NSG inbound rule allows traffic from any source (*). This is a critical exposure.',
    fix: "Replace sourceAddressPrefix: '*' with a specific CIDR or service tag.",
    check(result) {
      const resources = result.resourcesOfType(/networkSecurityGroups|azurerm_network_security_group|aws_security_group/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const rules = result.prop(r, 'securityRules') ??
                      result.prop(r, 'properties.securityRules');
        if (Array.isArray(rules)) {
          for (const rule of rules) {
            const props = rule.properties || rule;
            const dir = (props.direction || '').toLowerCase();
            const access = (props.access || '').toLowerCase();
            const src = props.sourceAddressPrefix;
            if (dir === 'inbound' && access === 'allow' && (src === '*' || src === '0.0.0.0/0' || src === 'Internet')) {
              return { passed: false, line: r.line, detail: `Rule '${rule.name || 'unknown'}' allows all inbound traffic` };
            }
          }
        }
        // Terraform ingress block
        const ingress = result.prop(r, 'ingress');
        if (ingress && typeof ingress === 'object') {
          const cidr = ingress.cidr_blocks;
          if (Array.isArray(cidr) && cidr.includes('0.0.0.0/0')) {
            return { passed: false, line: r.line, detail: 'Security group ingress allows 0.0.0.0/0' };
          }
        }
      }
      return true;
    }
  },
  {
    id: 'NET-002', cat: 'Networking', sev: 'HIGH',
    name: 'SSH port 22 open to internet (CIS 6.2)',
    desc: 'Port 22 is accessible from 0.0.0.0/0. Use Azure Bastion or restrict to known IPs.',
    fix: 'Remove port 22 from public inbound rules. Use AzureBastionSubnet.',
    check(result) {
      const resources = result.resourcesOfType(/networkSecurityGroups|azurerm_network_security_group|aws_security_group/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const rules = result.prop(r, 'securityRules') ??
                      result.prop(r, 'properties.securityRules') ?? [];
        if (Array.isArray(rules)) {
          for (const rule of rules) {
            const props = rule.properties || rule;
            const port = String(props.destinationPortRange || props.to_port || '');
            const src = String(props.sourceAddressPrefix || props.cidr_blocks || '');
            const dir = (props.direction || 'inbound').toLowerCase();
            const access = (props.access || 'allow').toLowerCase();
            if (dir === 'inbound' && access === 'allow' &&
                (port === '22' || port === '*') &&
                (src === '*' || src === '0.0.0.0/0' || src === 'Internet')) {
              return { passed: false, line: r.line, detail: 'SSH port 22 is open to the internet' };
            }
          }
        }
      }
      return true;
    }
  },
  {
    id: 'NET-003', cat: 'Networking', sev: 'HIGH',
    name: 'RDP port 3389 open to internet (CIS 6.3)',
    desc: 'Port 3389 is accessible from 0.0.0.0/0. Use Azure Bastion.',
    fix: 'Remove port 3389 from public inbound rules. Use Azure Bastion.',
    check(result) {
      const resources = result.resourcesOfType(/networkSecurityGroups|azurerm_network_security_group|aws_security_group/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const rules = result.prop(r, 'securityRules') ??
                      result.prop(r, 'properties.securityRules') ?? [];
        if (Array.isArray(rules)) {
          for (const rule of rules) {
            const props = rule.properties || rule;
            const port = String(props.destinationPortRange || props.to_port || '');
            const src = String(props.sourceAddressPrefix || '');
            const dir = (props.direction || 'inbound').toLowerCase();
            const access = (props.access || 'allow').toLowerCase();
            if (dir === 'inbound' && access === 'allow' &&
                (port === '3389' || port === '*') &&
                (src === '*' || src === '0.0.0.0/0' || src === 'Internet')) {
              return { passed: false, line: r.line, detail: 'RDP port 3389 is open to the internet' };
            }
          }
        }
      }
      return true;
    }
  },
  {
    id: 'NET-004', cat: 'Networking', sev: 'MEDIUM',
    name: 'VM has public IP address attached',
    desc: 'VMs should not have public IPs unless explicitly required.',
    fix: 'Remove publicIPAllocationMethod or set publicIPAddress to null.',
    check(result) {
      const resources = result.resourcesOfType(/Compute\/virtualMachines|azurerm_virtual_machine|azurerm_linux_virtual_machine|azurerm_windows_virtual_machine/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const pubIp = result.prop(r, 'publicIPAllocationMethod') ??
                      result.prop(r, 'properties.publicIPAllocationMethod');
        if (pubIp === 'Static' || pubIp === 'Dynamic') {
          return { passed: false, line: r.line, detail: `VM has publicIPAllocationMethod: ${pubIp}` };
        }
      }
      return true;
    }
  },

  /* ── IAM ────────────────────────────────────────────── */
  {
    id: 'IAM-001', cat: 'IAM', sev: 'CRITICAL',
    name: 'Owner role assigned at broad scope (CIS 1.15)',
    desc: 'Owner role grants full control including RBAC. Must not be assigned broadly.',
    fix: 'Replace Owner with Contributor or a custom role at resource scope.',
    check(result) {
      const resources = result.resourcesOfType(/Authorization\/roleAssignments|azurerm_role_assignment/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const roleId = result.prop(r, 'roleDefinitionId') ??
                       result.prop(r, 'properties.roleDefinitionId') ??
                       result.prop(r, 'role_definition_name');
        if (typeof roleId === 'string' && roleId.toLowerCase().includes('owner')) {
          return { passed: false, line: r.line, detail: 'Owner role assignment detected' };
        }
      }
      return true;
    }
  },
  {
    id: 'IAM-002', cat: 'IAM', sev: 'HIGH',
    name: 'Hardcoded credentials detected',
    desc: 'Passwords or secrets are hardcoded in the template. Use Key Vault references.',
    fix: 'Replace with a @secure() parameter or Key Vault secret reference.',
    check(result) {
      if (result.hasHardcodedSecrets()) {
        return { passed: false, line: 0, detail: 'Hardcoded secret or password found in parameter default value' };
      }
      return true;
    }
  },
  {
    id: 'IAM-003', cat: 'IAM', sev: 'HIGH',
    name: 'Managed Identity not configured',
    desc: 'Resources should use Managed Identity rather than service principal credentials.',
    fix: "identity: { type: 'SystemAssigned' }",
    check(result) {
      const resources = result.resourcesOfType(/Compute\/virtualMachines|ContainerService\/managedClusters|Web\/sites|azurerm_virtual_machine|azurerm_kubernetes_cluster|azurerm_linux_virtual_machine/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const identity = result.prop(r, 'identity') ??
                         result.prop(r, 'identity.type');
        if (!identity) {
          return { passed: false, line: r.line, detail: `Resource '${r.name}' has no Managed Identity configured` };
        }
      }
      return true;
    }
  },
  {
    id: 'IAM-004', cat: 'IAM', sev: 'MEDIUM',
    name: 'principalType not specified on role assignment',
    desc: 'Missing principalType can allow privilege escalation via type confusion.',
    fix: "properties: { principalType: 'ServicePrincipal' }",
    check(result) {
      const resources = result.resourcesOfType(/Authorization\/roleAssignments|azurerm_role_assignment/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const pt = result.prop(r, 'principalType') ??
                   result.prop(r, 'properties.principalType');
        if (!pt) return { passed: false, line: r.line, detail: 'principalType not set on role assignment' };
      }
      return true;
    }
  },

  /* ── OBSERVABILITY ──────────────────────────────────── */
  {
    id: 'OBS-001', cat: 'Observability', sev: 'HIGH',
    name: 'Diagnostic settings not configured (CIS 5.x)',
    desc: 'Resources should route logs to Log Analytics for audit and alerting.',
    fix: 'Add a Microsoft.Insights/diagnosticSettings resource.',
    check(result) {
      if (!result.resources().length) return null;
      return result.hasDiagnosticSettings() ? true : false;
    }
  },
  {
    id: 'OBS-002', cat: 'Observability', sev: 'MEDIUM',
    name: 'Log Analytics workspace not referenced',
    desc: 'A Log Analytics Workspace should be linked for centralised log collection.',
    fix: 'workspaceId: logAnalyticsWorkspace.id',
    check(result) {
      if (!result.resources().length) return null;
      return result.hasLogAnalytics() ? true : false;
    }
  },
  {
    id: 'OBS-003', cat: 'Observability', sev: 'LOW',
    name: 'Log retention below 365 days (CIS 5.1.2)',
    desc: 'Retention policy must be at least 365 days for compliance.',
    fix: 'retentionPolicy: { days: 365, enabled: true }',
    check(result) {
      const diagResources = result.resourcesOfType(/Insights\/diagnosticSettings|azurerm_monitor_diagnostic_setting/i);
      if (!diagResources.length) return null;
      for (const r of diagResources) {
        const days = result.prop(r, 'retentionPolicy.days') ??
                     result.prop(r, 'retention_policy.days') ??
                     result.prop(r, 'days');
        if (typeof days === 'number' && days < 365) {
          return { passed: false, line: r.line, detail: `Retention is ${days} days — must be >= 365` };
        }
      }
      return true;
    }
  },

  /* ── ENCRYPTION ─────────────────────────────────────── */
  {
    id: 'ENC-001', cat: 'Encryption', sev: 'HIGH',
    name: 'Encryption at rest not explicitly enabled (CIS 7.x)',
    desc: 'Storage and database resources should explicitly enable encryption at rest.',
    fix: 'encryption: { services: { blob: { enabled: true }, file: { enabled: true } } }',
    check(result) {
      const resources = result.resourcesOfType(/Storage\/storageAccounts|Compute\/disks|azurerm_storage_account|azurerm_managed_disk/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const encEnabled = result.prop(r, 'encryption.services.blob.enabled') ??
                           result.prop(r, 'encryption.enabled');
        if (encEnabled === false) {
          return { passed: false, line: r.line, detail: 'Encryption at rest is explicitly disabled' };
        }
      }
      return true;
    }
  },
  {
    id: 'ENC-002', cat: 'Encryption', sev: 'HIGH',
    name: 'Database TLS not enforced (CIS 4.3)',
    desc: 'Database connections must enforce TLS to protect data in transit.',
    fix: "sslEnforcement: 'Enabled'  or  require_secure_transport = true",
    check(result) {
      const resources = result.resourcesOfType(/DBforMySQL|DBforPostgreSQL|DBforMariaDB|azurerm_mysql|azurerm_postgresql/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const ssl = result.prop(r, 'sslEnforcement') ??
                    result.prop(r, 'properties.sslEnforcement') ??
                    result.prop(r, 'require_secure_transport');
        if (ssl === 'Disabled' || ssl === false) {
          return { passed: false, line: r.line, detail: 'Database TLS/SSL is disabled' };
        }
      }
      return true;
    }
  },

  /* ── KUBERNETES ─────────────────────────────────────── */
  {
    id: 'AKS-001', cat: 'Kubernetes', sev: 'HIGH',
    name: 'AKS RBAC must be enabled',
    desc: 'Kubernetes RBAC controls pod and API access. Must be enabled.',
    fix: 'properties: { enableRBAC: true }',
    check(result) {
      const resources = result.resourcesOfType(/ContainerService\/managedClusters|azurerm_kubernetes_cluster|aws_eks_cluster|google_container_cluster/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const rbac = result.prop(r, 'enableRBAC') ??
                     result.prop(r, 'properties.enableRBAC') ??
                     result.prop(r, 'role_based_access_control_enabled') ??
                     result.prop(r, 'enable_rbac');
        if (rbac === false) return { passed: false, line: r.line, detail: 'AKS RBAC is disabled' };
      }
      return true;
    }
  },
  {
    id: 'AKS-002', cat: 'Kubernetes', sev: 'HIGH',
    name: 'AKS network policy not configured',
    desc: 'Network policy controls pod-to-pod traffic. Required for zero-trust K8s.',
    fix: "networkProfile: { networkPolicy: 'calico' }",
    check(result) {
      const resources = result.resourcesOfType(/ContainerService\/managedClusters|azurerm_kubernetes_cluster/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const netPol = result.prop(r, 'networkPolicy') ??
                       result.prop(r, 'networkProfile.networkPolicy') ??
                       result.prop(r, 'network_policy');
        if (!netPol) return { passed: false, line: r.line, detail: 'No network policy configured on AKS cluster' };
      }
      return true;
    }
  },
  {
    id: 'AKS-003', cat: 'Kubernetes', sev: 'MEDIUM',
    name: 'AKS cluster autoscaler not enabled',
    desc: 'Autoscaler should be enabled to handle variable load without manual intervention.',
    fix: 'enableAutoScaling: true with minCount and maxCount defined.',
    check(result) {
      const resources = result.resourcesOfType(/ContainerService\/managedClusters|azurerm_kubernetes_cluster/i);
      if (!resources.length) return null;
      for (const r of resources) {
        const autoScale = result.prop(r, 'enableAutoScaling') ??
                          result.prop(r, 'enable_auto_scaling');
        if (autoScale === false || autoScale === undefined) {
          return { passed: false, line: r.line, detail: 'Cluster autoscaler not enabled' };
        }
      }
      return true;
    }
  },

  /* ── IaC QUALITY ────────────────────────────────────── */
  {
    id: 'IAC-001', cat: 'IaC Quality', sev: 'HIGH',
    name: 'Hardcoded secret in template',
    desc: 'Secrets must not appear in IaC templates. Use Key Vault or environment variables.',
    fix: 'Replace with a @secure() parameter or Key Vault secret reference.',
    check(result) {
      return result.hasHardcodedSecrets()
        ? { passed: false, line: 0, detail: 'Hardcoded secret or password found in template' }
        : true;
    }
  },
  {
    id: 'IAC-002', cat: 'IaC Quality', sev: 'MEDIUM',
    name: 'Bicep API version is outdated (pre-2022)',
    desc: 'Resource API versions should be 2022 or newer.',
    fix: 'Update resource API version to 2023-01-01 or latest stable.',
    check(result) {
      if (result.format !== 'bicep' && result.format !== 'arm') return null;
      for (const r of result.resources()) {
        const yr = result.apiVersionYear(r);
        if (yr !== null && yr < 2022) {
          return { passed: false, line: r.line, detail: `Resource '${r.name}' uses API version ${r.apiVersion} (pre-2022)` };
        }
      }
      return true;
    }
  },
  {
    id: 'IAC-003', cat: 'IaC Quality', sev: 'LOW',
    name: 'No output values defined',
    desc: 'Modules should define outputs (IDs, URIs) for dependent resources.',
    fix: 'output storageId string = storageAccount.id',
    check(result) {
      if (!result.resources().length) return null;
      return result.hasOutputs() ? true : false;
    }
  },
  {
    id: 'IAC-004', cat: 'IaC Quality', sev: 'LOW',
    name: 'Bicep parameters missing @description decorator',
    desc: 'All parameters should have @description() for documentation.',
    fix: "@description('The location for this resource')\nparam location string",
    check(result) {
      if (result.format !== 'bicep') return null;
      const params = result.paramNodes();
      if (!params.length) return null;
      const missing = params.filter(p => !p.decorators || !p.decorators.includes('description'));
      if (missing.length > 0) {
        return { passed: false, line: missing[0].line, detail: `${missing.length} parameter(s) missing @description decorator` };
      }
      return true;
    }
  },

  /* ── TERRAFORM ──────────────────────────────────────── */
  {
    id: 'TF-001', cat: 'Terraform', sev: 'HIGH',
    name: 'No remote state backend configured',
    desc: 'Terraform state must be stored remotely with locking. Local state is not production-safe.',
    fix: 'terraform { backend "azurerm" { ... } }',
    check(result) {
      if (result.format !== 'terraform') return null;
      return result.hasRemoteBackend() ? true
        : { passed: false, line: 0, detail: 'No backend block found in terraform configuration' };
    }
  },
  {
    id: 'TF-002', cat: 'Terraform', sev: 'MEDIUM',
    name: 'Provider version not pinned',
    desc: 'Unpinned providers can cause unexpected breaking changes on terraform init.',
    fix: 'version = "~> 3.0" inside required_providers block.',
    check(result) {
      if (result.format !== 'terraform') return null;
      return result.hasProviderVersionPin() ? true
        : { passed: false, line: 0, detail: 'No version constraint in required_providers' };
    }
  },
  {
    id: 'TF-003', cat: 'Terraform', sev: 'LOW',
    name: 'required_version not set',
    desc: 'required_version ensures consistent Terraform CLI versions across the team.',
    fix: 'terraform { required_version = ">= 1.5.0" }',
    check(result) {
      if (result.format !== 'terraform') return null;
      return result.hasRequiredVersion() ? true
        : { passed: false, line: 0, detail: 'required_version not set in terraform block' };
    }
  },

  /* ── BICEP SPECIFIC ─────────────────────────────────── */
  {
    id: 'BCP-001', cat: 'Bicep', sev: 'LOW',
    name: 'targetScope not declared',
    desc: 'Bicep files should declare targetScope for clarity and portability.',
    fix: "targetScope = 'subscription'",
    check(result) {
      if (result.format !== 'bicep') return null;
      if (!result.resources().length && !result.paramNodes().length) return null;
      return result.hasTargetScope() ? true
        : { passed: false, line: 1, detail: 'targetScope not declared' };
    }
  },
];

/**
 * Run all smart rules against a source template.
 * Returns an array of { rule, passed, line, detail } objects.
 */
function runSmartRules(source, format) {
  const result = parse(source, format);
  const findings = [];

  for (const rule of SMART_RULES) {
    let outcome;
    try {
      outcome = rule.check(result);
    } catch (e) {
      // Rule threw — skip silently
      continue;
    }

    if (outcome === null) continue; // not applicable

    if (outcome === true) {
      findings.push({ rule, passed: true, line: 0, detail: null });
    } else if (outcome === false) {
      findings.push({ rule, passed: false, line: 0, detail: null });
    } else if (typeof outcome === 'object') {
      findings.push({ rule, passed: outcome.passed, line: outcome.line || 0, detail: outcome.detail || null });
    }
  }

  return findings;
}

module.exports = { SMART_RULES, runSmartRules };
