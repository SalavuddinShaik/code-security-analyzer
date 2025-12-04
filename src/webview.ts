import * as vscode from "vscode";
import {
  getComplianceMapping,
  generateComplianceSummary,
} from "./complianceMapping";

export class SecurityDashboardPanel {
  public static currentPanel: SecurityDashboardPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];

  private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
    this.panel = panel;
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
    this.panel.webview.html = this.getWebviewContent();
  }

  public static createOrShow(extensionUri: vscode.Uri) {
    const column = vscode.window.activeTextEditor
      ? vscode.window.activeTextEditor.viewColumn
      : undefined;

    if (SecurityDashboardPanel.currentPanel) {
      SecurityDashboardPanel.currentPanel.panel.reveal(column);
      return SecurityDashboardPanel.currentPanel;
    }

    const panel = vscode.window.createWebviewPanel(
      "securityDashboard",
      "Security Dashboard",
      column || vscode.ViewColumn.One,
      {
        enableScripts: true,
        localResourceRoots: [extensionUri],
      }
    );

    SecurityDashboardPanel.currentPanel = new SecurityDashboardPanel(
      panel,
      extensionUri
    );
    return SecurityDashboardPanel.currentPanel;
  }

  public updateVulnerabilities(vulnerabilities: any[]) {
    // generate compliance summary
    const vulnerabilityTypes = vulnerabilities.map((v) => v.type);
    const complianceReport = generateComplianceSummary(vulnerabilityTypes);

    this.panel.webview.postMessage({
      command: "updateVulnerabilities",
      vulnerabilities: vulnerabilities,
      complianceReport: complianceReport,
    });
  }

  private getWebviewContent(): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Dashboard</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            padding: 20px;
        }
        h1 { margin-bottom: 20px; }
        h2 { 
            margin-top: 30px; 
            margin-bottom: 15px;
            border-bottom: 2px solid var(--vscode-panel-border);
            padding-bottom: 10px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: var(--vscode-editor-inactiveSelectionBackground);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .card h3 {
            margin: 0 0 10px 0;
            font-size: 14px;
        }
        .card .number {
            font-size: 36px;
            font-weight: bold;
        }
        .error { color: #f48771; }
        .warning { color: #cca700; }
        .success { color: #89d185; }
        
        .compliance-section {
            background: var(--vscode-editor-inactiveSelectionBackground);
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            border-left: 4px solid #4ec9b0;
        }
        .compliance-section h3 {
            margin-top: 0;
            color: #4ec9b0;
        }
        .compliance-report {
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            font-size: 12px;
            line-height: 1.6;
            background: var(--vscode-textBlockQuote-background);
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
        }
        
        .vulnerability-item {
            background: var(--vscode-editor-inactiveSelectionBackground);
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            border-left: 4px solid #f48771;
        }
        .vulnerability-item.compliance-relevant {
            border-left: 4px solid #4ec9b0;
        }
        .vulnerability-item strong {
            display: block;
            margin-bottom: 5px;
        }
        .vulnerability-item .compliance-badge {
            display: inline-block;
            background: #4ec9b0;
            color: #000;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 11px;
            margin-top: 5px;
        }
        .vulnerability-item .security-badge {
            display: inline-block;
            background: #6c757d;
            color: #fff;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 11px;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <h1>Security Analysis Dashboard</h1>
    <div class="summary">
        <div class="card">
            <h3>Total Issues</h3>
            <div class="number" id="total">0</div>
        </div>
        <div class="card">
            <h3>Critical</h3>
            <div class="number error" id="critical">0</div>
        </div>
        <div class="card">
            <h3>Warnings</h3>
            <div class="number warning" id="warnings">0</div>
        </div>
    </div>
    
    <div class="compliance-section">
        <h3>Security Compliance Analysis</h3>
        <div class="compliance-report" id="complianceReport">
            Analyzing security compliance...
        </div>
    </div>
    
    <h2>Detected Vulnerabilities</h2>
    <div id="vulnerabilityList"><p>No vulnerabilities detected yet.</p></div>
    
    <script>
        const vscode = acquireVsCodeApi();
        
        // Compliance-relevant vulnerability types (mapped to security standards)
        const complianceRelevantTypes = [
            'hardcoded-secret', 'hardcoded-password', 'hardcoded-api-key', 'hardcoded-jwt',
            'sql-injection', 'sql-injection-concat', 'sql-injection-insert', 'sql-injection-update', 
            'sql-injection-delete', 'sql-injection-query', 'sql-injection-template',
            'xss', 'xss-innerHTML', 'xss-document-write', 'xss-jquery-html', 'xss-outerHTML',
            'code-injection-eval',
            'insecure-storage',
            'weak-random', 'weak-random-number', 'weak-random-generation',
            'sensitive-data-logging',
            'credentials-in-url',
            'weak-hash-algorithm', 'weak-encryption', 'hardcoded-encryption-key'
        ];
        
        function isComplianceRelevant(vulnType) {
            return complianceRelevantTypes.some(type => 
                vulnType === type || vulnType.startsWith(type.split('-')[0] + '-')
            );
        }
        
        window.addEventListener('message', event => {
            const message = event.data;
            if (message.command === 'updateVulnerabilities') {
                updateDashboard(message.vulnerabilities, message.complianceReport);
            }
        });

        function updateDashboard(vulnerabilities, complianceReport) {
            const critical = vulnerabilities.filter(v => v.severity === 8).length;
            const warnings = vulnerabilities.filter(v => v.severity === 4).length;
            
            document.getElementById('total').textContent = vulnerabilities.length;
            document.getElementById('critical').textContent = critical;
            document.getElementById('warnings').textContent = warnings;
            
            if (complianceReport) {
                document.getElementById('complianceReport').textContent = complianceReport;
            }
            
            if (vulnerabilities.length === 0) {
                document.getElementById('vulnerabilityList').innerHTML = '<p>No vulnerabilities detected. Code appears secure.</p>';
                document.getElementById('complianceReport').textContent = 'No security issues detected. Code appears compliant with security standards.';
                return;
            }
            
            const listHtml = vulnerabilities.map(v => {
                const messageParts = v.message.split('\\n');
                const mainMessage = messageParts[0];
                const complianceRelevant = isComplianceRelevant(v.type);
                const badgeHtml = complianceRelevant 
                    ? '<span class="compliance-badge">Compliance Risk</span>'
                    : '<span class="security-badge">Security Issue</span>';
                const itemClass = complianceRelevant ? 'vulnerability-item compliance-relevant' : 'vulnerability-item';
                
                return \`<div class="\${itemClass}">
                    <strong>\${v.type}</strong> - Line \${v.line + 1}
                    <p>\${mainMessage}</p>
                    \${badgeHtml}
                </div>\`;
            }).join('');
            
            document.getElementById('vulnerabilityList').innerHTML = listHtml;
        }
    </script>
</body>
</html>`;
  }

  public dispose() {
    SecurityDashboardPanel.currentPanel = undefined;
    this.panel.dispose();
    while (this.disposables.length) {
      const disposable = this.disposables.pop();
      if (disposable) {
        disposable.dispose();
      }
    }
  }
}
