# Contributing to CloudCheck

Thank you for your interest in contributing. CloudCheck is a VS Code extension that runs compliance checks on Bicep, Terraform, and ARM templates against the CIS Azure Benchmark and Microsoft CAF naming conventions.

---

## How to add a new rule

All rules live in `src/rules-smart.js`. Each rule is an object in the `SMART_RULES` array.

### Rule structure

```javascript
{
  id: 'CAT-001',        // Unique ID. Format: category abbreviation + number.
  cat: 'Category',      // Category name shown in the Problems panel.
  sev: 'HIGH',          // Severity: CRITICAL, HIGH, MEDIUM, or LOW.
  name: 'Rule name',    // Short description shown in the Problems panel.
  desc: 'Full description of the issue.',
  fix: 'Exact remediation code snippet.',
  check(result) {
    // result is a ParseResult object from src/parser.js
    // Return null if the rule does not apply to this template.
    // Return true if the check passes.
    // Return false if the check fails (line 0).
    // Return { passed: false, line: N, detail: 'message' } for a specific location.
  }
}
```

### ParseResult methods available in check()

```javascript
result.resources()                    // All resource nodes
result.resourcesOfType(/pattern/)     // Resources matching a type regex
result.prop(resource, 'path.to.prop') // Get a property value from a resource
result.paramNodes()                   // All param nodes
result.outputNodes()                  // All output nodes
result.hasTag('Environment')          // Check if any tag key exists
result.hasDiagnosticSettings()        // Check for diagnostic settings resource
result.hasLogAnalytics()              // Check for Log Analytics reference
result.hasRemoteBackend()             // Terraform: check for remote backend
result.hasProviderVersionPin()        // Terraform: check for version pin
result.hasHardcodedSecrets()          // Check for hardcoded passwords or secrets
result.format                         // 'bicep', 'terraform', or 'arm'
```

### Example: adding a new rule

```javascript
{
  id: 'STG-005', cat: 'Storage', sev: 'HIGH',
  name: 'Storage account should disable shared key access',
  desc: 'Shared key access allows full access to storage. Use Azure AD instead.',
  fix: "properties: { allowSharedKeyAccess: false }",
  check(result) {
    const resources = result.resourcesOfType(/Storage\/storageAccounts/i);
    if (!resources.length) return null;
    for (const r of resources) {
      const val = result.prop(r, 'allowSharedKeyAccess');
      if (val === true) {
        return { passed: false, line: r.line, detail: 'allowSharedKeyAccess is true' };
      }
    }
    return true;
  }
}
```

---

## Rule ID conventions

| Prefix | Category |
|---|---|
| NAM | Naming |
| TAG | Tags |
| STG | Storage |
| KV | Key Vault |
| NET | Networking |
| IAM | IAM and RBAC |
| OBS | Observability |
| ENC | Encryption |
| AKS | Kubernetes |
| IAC | IaC Quality |
| TF | Terraform |
| BCP | Bicep |

---

## Running locally

```bash
cd cloudcheck
npm install
code .
```

Press F5 in VS Code to open the Extension Development Host. Open any .bicep or .tf file and save to trigger the checks.

---

## Submitting a rule

1. Add your rule to `src/rules-smart.js`.
2. Test it against a template that should fail and one that should pass.
3. Open a pull request with a brief description of what the rule catches and its CIS or CAF reference.

---

## Reporting a false positive

Open an issue at [github.com/headspace222/cloudcheck/issues](https://github.com/headspace222/cloudcheck/issues) with the template that triggers the false positive and the rule ID.
