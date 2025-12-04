import * as vscode from "vscode";
import { Vulnerability } from "./detector";
import { generateComplianceSummary } from "./complianceMapping";

export interface SecurityReport {
  projectName: string;
  fileName: string;
  timestamp: Date;
  summary: {
    totalIssues: number;
    critical: number;
    warnings: number;
  };
  vulnerabilities: Vulnerability[];
  complianceReport: string;
}

export class ReportGenerator {
  public generateReport(
    vulnerabilities: Vulnerability[],
    fileName: string,
    projectName?: string
  ): SecurityReport {
    const critical = vulnerabilities.filter(
      (v) => v.severity === vscode.DiagnosticSeverity.Error
    ).length;

    const warnings = vulnerabilities.filter(
      (v) => v.severity === vscode.DiagnosticSeverity.Warning
    ).length;

    const vulnerabilityTypes = vulnerabilities.map((v) => v.type);
    const complianceReport = generateComplianceSummary(vulnerabilityTypes);

    return {
      projectName: projectName || "Unknown Project",
      fileName: fileName,
      timestamp: new Date(),
      summary: {
        totalIssues: vulnerabilities.length,
        critical: critical,
        warnings: warnings,
      },
      vulnerabilities: vulnerabilities,
      complianceReport: complianceReport,
    };
  }

  public generateHTML(report: SecurityReport): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - ${this.escapeHtml(report.projectName)}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .header {
            border-bottom: 3px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: #007acc;
            font-size: 32px;
            margin-bottom: 10px;
        }
        
        .header .meta {
            color: #666;
            font-size: 14px;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 8px;
            text-align: center;
        }
        
        .summary-card.critical {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
        
        .summary-card.warning {
            background: linear-gradient(135deg, #ffd89b 0%, #f59e0b 100%);
        }
        
        .summary-card h3 {
            font-size: 14px;
            font-weight: 500;
            opacity: 0.9;
            margin-bottom: 10px;
        }
        
        .summary-card .number {
            font-size: 48px;
            font-weight: bold;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            color: #007acc;
            font-size: 24px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }
        
        .compliance-section {
            background: #f0f9ff;
            border-left: 4px solid #0ea5e9;
            padding: 20px;
            border-radius: 4px;
            margin-bottom: 30px;
        }
        
        .compliance-section h3 {
            color: #0ea5e9;
            margin-bottom: 15px;
        }
        
        .compliance-report {
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            font-size: 13px;
            line-height: 1.8;
            color: #1e3a8a;
        }
        
        .vulnerability {
            background: white;
            border: 1px solid #e0e0e0;
            border-left: 4px solid #f59e0b;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 4px;
        }
        
        .vulnerability.critical {
            border-left-color: #ef4444;
        }
        
        .vulnerability-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .vulnerability-type {
            font-weight: bold;
            font-size: 16px;
            color: #1f2937;
        }
        
        .vulnerability-severity {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-critical {
            background: #fee2e2;
            color: #991b1b;
        }
        
        .severity-warning {
            background: #fef3c7;
            color: #92400e;
        }
        
        .vulnerability-location {
            color: #666;
            font-size: 14px;
            margin-bottom: 10px;
        }
        
        .vulnerability-message {
            color: #374151;
            line-height: 1.6;
        }
        
        .compliance-badge {
            display: inline-block;
            background: #0ea5e9;
            color: white;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            margin-top: 8px;
        }
        
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #e0e0e0;
            text-align: center;
            color: #666;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Analysis Report</h1>
            <div class="meta">
                <strong>Project:</strong> ${this.escapeHtml(
                  report.projectName
                )} |
                <strong>File:</strong> ${this.escapeHtml(report.fileName)} |
                <strong>Generated:</strong> ${report.timestamp.toLocaleString()}
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Issues</h3>
                <div class="number">${report.summary.totalIssues}</div>
            </div>
            <div class="summary-card critical">
                <h3>Critical</h3>
                <div class="number">${report.summary.critical}</div>
            </div>
            <div class="summary-card warning">
                <h3>Warnings</h3>
                <div class="number">${report.summary.warnings}</div>
            </div>
        </div>
        
        ${this.generateComplianceSection(report.complianceReport)}
        
        <div class="section">
            <h2>Detected Vulnerabilities</h2>
            ${this.generateVulnerabilityList(report.vulnerabilities)}
        </div>
        
        <div class="footer">
            <p>Generated by Code Security Analyzer</p>
            <p>Report generated on ${report.timestamp.toLocaleString()}</p>
        </div>
    </div>
</body>
</html>`;
  }

  private generateComplianceSection(complianceReport: string): string {
    if (!complianceReport || complianceReport.includes("No security issues")) {
      return `
        <div class="compliance-section">
            <h3>Security Compliance Status</h3>
            <p style="color: #059669; font-weight: 600;">No security issues detected. Code appears compliant with security standards.</p>
        </div>`;
    }

    return `
        <div class="compliance-section">
            <h3>Security Compliance Analysis</h3>
            <div class="compliance-report">${this.escapeHtml(
              complianceReport
            )}</div>
        </div>`;
  }

  private generateVulnerabilityList(vulnerabilities: Vulnerability[]): string {
    if (vulnerabilities.length === 0) {
      return `<p style="color: #059669; font-weight: 600;">No vulnerabilities detected. Code appears secure.</p>`;
    }

    return vulnerabilities
      .map((vuln) => {
        const isCritical = vuln.severity === vscode.DiagnosticSeverity.Error;
        const severityClass = isCritical ? "critical" : "warning";
        const severityText = isCritical ? "Critical" : "Warning";
        const severityBadgeClass = isCritical
          ? "severity-critical"
          : "severity-warning";

        return `
        <div class="vulnerability ${severityClass}">
            <div class="vulnerability-header">
                <span class="vulnerability-type">${this.escapeHtml(
                  this.formatType(vuln.type)
                )}</span>
                <span class="vulnerability-severity ${severityBadgeClass}">${severityText}</span>
            </div>
            <div class="vulnerability-location">
                Line ${vuln.line + 1}, Column ${vuln.column}
            </div>
            <div class="vulnerability-message">
                ${this.escapeHtml(vuln.message)}
            </div>
            <span class="compliance-badge">Compliance Risk</span>
        </div>`;
      })
      .join("");
  }

  private formatType(type: string): string {
    return type
      .split("-")
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(" ");
  }

  private escapeHtml(text: string): string {
    const map: { [key: string]: string } = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;",
    };
    return text.replace(/[&<>"']/g, (m) => map[m]);
  }
}
