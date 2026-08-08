'use strict';

const vscode = require('vscode');
const { RULES } = require('./rules');
const { detectFormat, formatFromLanguageId } = require('./detector');

// Diagnostic collection — owns all CloudCheck markers in the Problems panel
let diagnosticCollection;
let outputChannel;
let statusBarItem;

/**
 * Map severity string to VS Code DiagnosticSeverity.
 * CRITICAL / HIGH -> Error (red squiggle)
 * MEDIUM          -> Warning (yellow squiggle)
 * LOW             -> Information (blue squiggle)
 */
function toVscodeSeverity(sev) {
  if (sev === 'CRITICAL' || sev === 'HIGH') return vscode.DiagnosticSeverity.Error;
  if (sev === 'MEDIUM') return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

/**
 * Find the best line number for a diagnostic.
 * Tries to find the first line containing a keyword from the rule fix string.
 * Falls back to line 0.
 */
function findBestLine(lines, rule, text) {
  // For known patterns, try to find a relevant line
  const patterns = {
    'STG-001': /allowBlobPublicAccess/i,
    'STG-002': /supportsHttpsTrafficOnly/i,
    'STG-003': /minimumTlsVersion|TLS1_0|TLS1_1/i,
    'STG-004': /defaultAction/i,
    'KV-001': /enableSoftDelete/i,
    'KV-002': /enablePurgeProtection/i,
    'KV-003': /enableRbacAuthorization/i,
    'NET-001': /sourceAddressPrefix\s*:\s*['"]\*/i,
    'NET-002': /destinationPortRange.*22|to_port.*22/i,
    'NET-003': /destinationPortRange.*3389|to_port.*3389/i,
    'IAM-001': /Owner/i,
    'IAM-002': /adminPassword|password\s*=|client_secret/i,
    'TF-001': /terraform\s*{/i,
    'AKS-001': /enableRBAC|role_based_access_control/i,
  };

  const pattern = patterns[rule.id];
  if (pattern) {
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) return i;
    }
  }

  // Generic: find first line mentioning the resource type
  const resourcePatterns = {
    'Storage': /storageAccount|storage_account/i,
    'Key Vault': /KeyVault|key_vault/i,
    'Networking': /networkSecurityGroup|securityRule|security_group/i,
    'IAM': /roleAssignment|role_assignment/i,
    'Kubernetes': /managedClusters|kubernetes_cluster/i,
    'Terraform': /^terraform\s*{/im,
    'Bicep': /^param\s+|^resource\s+/im,
  };

  const catPattern = resourcePatterns[rule.cat];
  if (catPattern) {
    for (let i = 0; i < lines.length; i++) {
      if (catPattern.test(lines[i])) return i;
    }
  }

  return 0;
}

/**
 * Run all applicable rules against the document text.
 * Returns an array of VS Code Diagnostic objects.
 */
function runRules(document) {
  const config = vscode.workspace.getConfiguration('cloudcheck');
  if (!config.get('enable', true)) return [];

  const text = document.getText();
  const lines = text.split('\n');
  const langId = document.languageId;

  // Detect format: prefer content detection, use languageId as fallback hint
  let fmt = detectFormat(text);
  if (fmt === 'unknown') {
    const hint = formatFromLanguageId(langId);
    if (hint) fmt = hint;
  }

  // If still unknown and it's a JSON file, skip (could be any JSON)
  if (fmt === 'unknown' && langId === 'json') return [];
  if (fmt === 'unknown') return [];

  const minSev = config.get('severity', 'all');
  const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const minSevIdx = minSev === 'all' ? 4 : sevOrder.indexOf(minSev.toUpperCase());

  const diagnostics = [];

  for (const rule of RULES) {
    let result;
    try {
      result = rule.check(text, fmt);
    } catch (e) {
      continue;
    }

    if (result === null || result === true) continue;

    // Check minimum severity filter
    const ruleSevIdx = sevOrder.indexOf(rule.sev);
    if (ruleSevIdx > minSevIdx) continue;

    // Find best line for this diagnostic
    const lineIdx = findBestLine(lines, rule, text);
    const line = lines[lineIdx] || '';
    const range = new vscode.Range(
      new vscode.Position(lineIdx, 0),
      new vscode.Position(lineIdx, Math.max(line.length, 1))
    );

    const diag = new vscode.Diagnostic(
      range,
      `[CloudCheck ${rule.id}] ${rule.name}\n${rule.desc}\nFix: ${rule.fix}`,
      toVscodeSeverity(rule.sev)
    );

    diag.source = 'CloudCheck';
    diag.code = {
      value: rule.id,
      target: vscode.Uri.parse(`https://github.com/cloudcheck/cloudcheck/blob/main/docs/rules/${rule.id}.md`)
    };
    diag.tags = rule.sev === 'LOW' ? [vscode.DiagnosticTag.Hint] : [];

    diagnostics.push(diag);
  }

  return diagnostics;
}

/**
 * Run checks on a document and update the diagnostic collection.
 */
function checkDocument(document) {
  if (!isSupportedFile(document)) return;

  const diagnostics = runRules(document);
  diagnosticCollection.set(document.uri, diagnostics);

  updateStatusBar(diagnostics);
  logToOutput(document, diagnostics);
}

function isSupportedFile(document) {
  const ext = document.fileName.split('.').pop().toLowerCase();
  const supported = ['bicep', 'tf', 'json'];
  return supported.includes(ext) || ['bicep', 'terraform', 'arm-template'].includes(document.languageId);
}

function updateStatusBar(diagnostics) {
  const critHigh = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Error).length;
  const med = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Warning).length;

  if (diagnostics.length === 0) {
    statusBarItem.text = '$(check) CloudCheck';
    statusBarItem.tooltip = 'CloudCheck: No issues found';
    statusBarItem.backgroundColor = undefined;
    statusBarItem.color = new vscode.ThemeColor('statusBarItem.prominentForeground');
  } else if (critHigh > 0) {
    statusBarItem.text = `$(error) CloudCheck: ${critHigh} critical/high`;
    statusBarItem.tooltip = `CloudCheck: ${critHigh} critical/high, ${med} medium issues`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    statusBarItem.color = undefined;
  } else {
    statusBarItem.text = `$(warning) CloudCheck: ${med} issues`;
    statusBarItem.tooltip = `CloudCheck: ${med} medium/low issues`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    statusBarItem.color = undefined;
  }
  statusBarItem.show();
}

function logToOutput(document, diagnostics) {
  const fname = document.fileName.split('/').pop();
  const errors = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Error).length;
  const warnings = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Warning).length;
  const info = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Information).length;

  outputChannel.appendLine(`\n[${new Date().toLocaleTimeString()}] ${fname}`);
  outputChannel.appendLine(`  ${diagnostics.length} findings  |  ${errors} errors  |  ${warnings} warnings  |  ${info} info`);

  for (const d of diagnostics) {
    const prefix = d.severity === 0 ? 'ERR' : d.severity === 1 ? 'WARN' : 'INFO';
    outputChannel.appendLine(`  [${prefix}] Line ${d.range.start.line + 1}: ${d.message.split('\n')[0]}`);
  }
}

/**
 * Extension activation
 */
function activate(context) {
  diagnosticCollection = vscode.languages.createDiagnosticCollection('cloudcheck');
  context.subscriptions.push(diagnosticCollection);

  outputChannel = vscode.window.createOutputChannel('CloudCheck');
  context.subscriptions.push(outputChannel);

  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = 'cloudcheck.showOutput';
  context.subscriptions.push(statusBarItem);

  outputChannel.appendLine('CloudCheck activated. Watching .bicep, .tf, and ARM JSON files.');
  outputChannel.appendLine(`Rules loaded: ${RULES.length}`);

  // Check active document on startup
  if (vscode.window.activeTextEditor) {
    checkDocument(vscode.window.activeTextEditor.document);
  }

  // On save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      const config = vscode.workspace.getConfiguration('cloudcheck');
      if (config.get('lintOnSave', true)) checkDocument(doc);
    })
  );

  // On type (optional, default off)
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(e => {
      const config = vscode.workspace.getConfiguration('cloudcheck');
      if (config.get('lintOnType', false)) checkDocument(e.document);
    })
  );

  // On switch file
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor) checkDocument(editor.document);
    })
  );

  // On close — clear diagnostics
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument(doc => {
      diagnosticCollection.delete(doc.uri);
    })
  );

  // Command: run check manually
  context.subscriptions.push(
    vscode.commands.registerCommand('cloudcheck.runCheck', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage('CloudCheck: No active file.');
        return;
      }
      checkDocument(editor.document);
      const count = (diagnosticCollection.get(editor.document.uri) || []).length;
      vscode.window.showInformationMessage(
        count === 0
          ? 'CloudCheck: No issues found.'
          : `CloudCheck: ${count} issue${count > 1 ? 's' : ''} found. See Problems panel.`
      );
    })
  );

  // Command: show output panel
  context.subscriptions.push(
    vscode.commands.registerCommand('cloudcheck.showOutput', () => {
      outputChannel.show();
    })
  );

  statusBarItem.text = '$(shield) CloudCheck';
  statusBarItem.tooltip = 'CloudCheck: Ready';
  statusBarItem.show();
}

function deactivate() {
  diagnosticCollection?.clear();
  diagnosticCollection?.dispose();
}

module.exports = { activate, deactivate };
