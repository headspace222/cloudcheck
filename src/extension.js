'use strict';

const vscode = require('vscode');
const { runSmartRules } = require('./rules-smart');
const { detectFormat, formatFromLanguageId } = require('./detector');

let diagnosticCollection;
let outputChannel;
let statusBarItem;

function toVscodeSeverity(sev) {
  if (sev === 'CRITICAL' || sev === 'HIGH') return vscode.DiagnosticSeverity.Error;
  if (sev === 'MEDIUM') return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

function checkDocument(document) {
  if (!isSupportedFile(document)) return;

  const config = vscode.workspace.getConfiguration('cloudcheck');
  if (!config.get('enable', true)) return;

  const text = document.getText();
  const lines = text.split('\n');

  let fmt = detectFormat(text);
  if (fmt === 'unknown') {
    const hint = formatFromLanguageId(document.languageId);
    if (hint) fmt = hint;
  }
  if (fmt === 'unknown' && document.languageId === 'json') return;
  if (fmt === 'unknown') return;

  const minSev = config.get('severity', 'all');
  const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const minSevIdx = minSev === 'all' ? 4 : sevOrder.indexOf(minSev.toUpperCase());

  // Run smart rules engine
  const findings = runSmartRules(text, fmt);
  const diagnostics = [];

  for (const finding of findings) {
    if (finding.passed) continue;

    const ruleSevIdx = sevOrder.indexOf(finding.rule.sev);
    if (ruleSevIdx > minSevIdx) continue;

    // Use the exact line from the parser, fall back to line 0
    const lineIdx = Math.max(0, (finding.line || 1) - 1);
    const line = lines[lineIdx] || '';
    const range = new vscode.Range(
      new vscode.Position(lineIdx, 0),
      new vscode.Position(lineIdx, Math.max(line.trimEnd().length, 1))
    );

    // Build a clear message
    const msg = [
      `[CloudCheck ${finding.rule.id}] ${finding.rule.name}`,
      finding.detail || finding.rule.desc,
      `Fix: ${finding.rule.fix}`,
    ].join('\n');

    const diag = new vscode.Diagnostic(range, msg, toVscodeSeverity(finding.rule.sev));
    diag.source = 'CloudCheck';
    diag.code = {
      value: finding.rule.id,
      target: vscode.Uri.parse(`https://github.com/headspace222/cloudcheck/blob/main/docs/rules/${finding.rule.id}.md`)
    };

    diagnostics.push(diag);
  }

  diagnosticCollection.set(document.uri, diagnostics);
  updateStatusBar(diagnostics);
  logToOutput(document, findings, fmt);
}

function isSupportedFile(document) {
  const ext = document.fileName.split('.').pop().toLowerCase();
  return ['bicep', 'tf', 'json'].includes(ext) ||
         ['bicep', 'terraform', 'arm-template'].includes(document.languageId);
}

function updateStatusBar(diagnostics) {
  const critHigh = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Error).length;
  const med = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Warning).length;

  if (diagnostics.length === 0) {
    statusBarItem.text = '$(check) CloudCheck';
    statusBarItem.tooltip = 'CloudCheck: All checks passed';
    statusBarItem.backgroundColor = undefined;
  } else if (critHigh > 0) {
    statusBarItem.text = `$(error) CloudCheck: ${critHigh} critical/high`;
    statusBarItem.tooltip = `CloudCheck: ${critHigh} critical/high, ${med} medium issues`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  } else {
    statusBarItem.text = `$(warning) CloudCheck: ${med} issues`;
    statusBarItem.tooltip = `CloudCheck: ${med} medium/low issues`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  }
  statusBarItem.show();
}

function logToOutput(document, findings, fmt) {
  const fname = document.fileName.split(/[/\\]/).pop();
  const fails = findings.filter(f => !f.passed);
  const passes = findings.filter(f => f.passed);

  outputChannel.appendLine(`\n[${new Date().toLocaleTimeString()}] ${fname} (${fmt.toUpperCase()})`);
  outputChannel.appendLine(`  ${findings.length} checks | ${fails.length} failed | ${passes.length} passed`);

  for (const f of fails) {
    const prefix = (f.rule.sev === 'CRITICAL' || f.rule.sev === 'HIGH') ? 'ERR ' : 'WARN';
    const loc = f.line ? ` (line ${f.line})` : '';
    outputChannel.appendLine(`  [${prefix}] ${f.rule.id} ${f.rule.name}${loc}`);
    if (f.detail) outputChannel.appendLine(`         ${f.detail}`);
  }
}

function activate(context) {
  diagnosticCollection = vscode.languages.createDiagnosticCollection('cloudcheck');
  context.subscriptions.push(diagnosticCollection);

  outputChannel = vscode.window.createOutputChannel('CloudCheck');
  context.subscriptions.push(outputChannel);

  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = 'cloudcheck.showOutput';
  context.subscriptions.push(statusBarItem);

  outputChannel.appendLine('CloudCheck activated (AST parser v0.2.0)');
  outputChannel.appendLine('Watching .bicep, .tf, and ARM JSON files');

  if (vscode.window.activeTextEditor) {
    checkDocument(vscode.window.activeTextEditor.document);
  }

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      if (vscode.workspace.getConfiguration('cloudcheck').get('lintOnSave', true)) {
        checkDocument(doc);
      }
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(e => {
      if (vscode.workspace.getConfiguration('cloudcheck').get('lintOnType', false)) {
        checkDocument(e.document);
      }
    })
  );

  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor) checkDocument(editor.document);
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument(doc => {
      diagnosticCollection.delete(doc.uri);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('cloudcheck.runCheck', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) { vscode.window.showInformationMessage('CloudCheck: No active file.'); return; }
      checkDocument(editor.document);
      const count = (diagnosticCollection.get(editor.document.uri) || []).length;
      vscode.window.showInformationMessage(
        count === 0
          ? 'CloudCheck: All checks passed.'
          : `CloudCheck: ${count} issue${count > 1 ? 's' : ''} found. See Problems panel.`
      );
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('cloudcheck.showOutput', () => outputChannel.show())
  );

  statusBarItem.text = '$(shield) CloudCheck';
  statusBarItem.tooltip = 'CloudCheck: Ready (AST parser)';
  statusBarItem.show();
}

function deactivate() {
  diagnosticCollection?.clear();
  diagnosticCollection?.dispose();
}

module.exports = { activate, deactivate };
