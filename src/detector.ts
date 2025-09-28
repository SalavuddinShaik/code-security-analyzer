import * as vscode from "vscode";

export interface Vulnerability {
  type: string;
  line: number;
  column: number;
  endColumn: number;
  message: string;
  severity: vscode.DiagnosticSeverity;
}

export function detectVulnerabilities(text: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  const lines = text.split("\n");

  lines.forEach((line, lineIndex) => {
    // Detect hardcoded secrets
    detectHardcodedSecrets(line, lineIndex, vulnerabilities);

    // Detect SQL injection vulnerabilities
    detectSQLInjection(line, lineIndex, vulnerabilities);

    // Detect XSS vulnerabilities
    detectXSSVulnerabilities(line, lineIndex, vulnerabilities);
  });

  return vulnerabilities;
}

function detectHardcodedSecrets(
  line: string,
  lineIndex: number,
  vulnerabilities: Vulnerability[]
) {
  const secretPatterns = [
    {
      regex: /(?:api[_-]?key|apikey)\s*[:=]\s*['"`]([a-zA-Z0-9]{16,})['"`]/gi,
      type: "hardcoded-api-key",
      message: "Hardcoded API key detected - use environment variables instead",
      severity: vscode.DiagnosticSeverity.Error,
    },
    {
      regex: /(?:password|pwd)\s*[:=]\s*['"`]([^'"`]{8,})['"`]/gi,
      type: "hardcoded-password",
      message: "Hardcoded password detected - use secure configuration",
      severity: vscode.DiagnosticSeverity.Error,
    },
    {
      regex:
        /(?:secret|private[_-]?key)\s*[:=]\s*['"`]([a-zA-Z0-9+/]{20,})['"`]/gi,
      type: "hardcoded-secret",
      message: "Hardcoded secret detected - use secure key management",
      severity: vscode.DiagnosticSeverity.Error,
    },
    {
      regex:
        /(?:jwt|token)\s*[:=]\s*['"`](eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*)['"`]/gi,
      type: "hardcoded-jwt",
      message: "Hardcoded JWT token detected - generate tokens dynamically",
      severity: vscode.DiagnosticSeverity.Error,
    },
  ];

  secretPatterns.forEach((pattern) => {
    let match;
    while ((match = pattern.regex.exec(line)) !== null) {
      vulnerabilities.push({
        type: pattern.type,
        line: lineIndex,
        column: match.index,
        endColumn: match.index + match[0].length,
        message: pattern.message,
        severity: pattern.severity,
      });
    }
    pattern.regex.lastIndex = 0;
  });
}

function detectSQLInjection(
  line: string,
  lineIndex: number,
  vulnerabilities: Vulnerability[]
) {
  const sqlPatterns = [
    {
      regex: /['"]SELECT\s+.*['"][\s]*\+[\s]*\w+/gi,
      type: "sql-injection-concat",
      message:
        "Potential SQL injection: avoid string concatenation in SQL queries",
      severity: vscode.DiagnosticSeverity.Warning,
    },
    {
      regex: /['"]INSERT\s+INTO\s+.*['"][\s]*\+[\s]*\w+/gi,
      type: "sql-injection-insert",
      message:
        "Potential SQL injection in INSERT statement - use parameterized queries",
      severity: vscode.DiagnosticSeverity.Warning,
    },
    {
      regex: /['"]UPDATE\s+.*SET\s+.*['"][\s]*\+[\s]*\w+/gi,
      type: "sql-injection-update",
      message:
        "Potential SQL injection in UPDATE statement - use parameterized queries",
      severity: vscode.DiagnosticSeverity.Warning,
    },
    {
      regex: /['"]DELETE\s+FROM\s+.*['"][\s]*\+[\s]*\w+/gi,
      type: "sql-injection-delete",
      message:
        "Potential SQL injection in DELETE statement - use parameterized queries",
      severity: vscode.DiagnosticSeverity.Warning,
    },
    {
      regex: /\.query\s*\(\s*['"][^'"]*['"][\s]*\+[\s]*\w+/gi,
      type: "sql-injection-query",
      message:
        "Database query with string concatenation - use parameterized queries",
      severity: vscode.DiagnosticSeverity.Warning,
    },
    {
      regex: /WHERE\s+\w+\s*=\s*\$\{[^}]+\}/gi,
      type: "sql-injection-template",
      message:
        "SQL injection via template literals - use parameterized queries instead",
      severity: vscode.DiagnosticSeverity.Warning,
    },
  ];

  sqlPatterns.forEach((pattern) => {
    let match;
    while ((match = pattern.regex.exec(line)) !== null) {
      vulnerabilities.push({
        type: pattern.type,
        line: lineIndex,
        column: match.index,
        endColumn: match.index + match[0].length,
        message: pattern.message,
        severity: pattern.severity,
      });
    }
    pattern.regex.lastIndex = 0;
  });
}

function detectXSSVulnerabilities(
  line: string,
  lineIndex: number,
  vulnerabilities: Vulnerability[]
) {
  const xssPatterns = [
    {
      regex: /\.innerHTML\s*=\s*(?!['"][^'"]*['"])[^;]+/gi,
      type: "xss-innerHTML",
      message:
        "Potential XSS via innerHTML - sanitize user input or use textContent",
      severity: vscode.DiagnosticSeverity.Warning,
    },
    {
      regex: /document\.write\s*\(\s*(?!['"][^'"]*['"])[^)]+\)/gi,
      type: "xss-document-write",
      message:
        "Potential XSS via document.write - avoid or sanitize dynamic content",
      severity: vscode.DiagnosticSeverity.Warning,
    },
    {
      regex: /\$\([^)]*\)\.html\s*\(\s*(?!['"][^'"]*['"])[^)]+\)/gi,
      type: "xss-jquery-html",
      message:
        "Potential XSS via jQuery .html() - use .text() or sanitize input",
      severity: vscode.DiagnosticSeverity.Warning,
    },
    {
      regex: /\.outerHTML\s*=\s*(?!['"][^'"]*['"])[^;]+/gi,
      type: "xss-outerHTML",
      message: "Potential XSS via outerHTML - sanitize user input",
      severity: vscode.DiagnosticSeverity.Warning,
    },
    {
      regex: /eval\s*\(\s*(?!['"][^'"]*['"])[^)]+\)/gi,
      type: "code-injection-eval",
      message: "Code injection via eval() - avoid eval with dynamic content",
      severity: vscode.DiagnosticSeverity.Error,
    },
  ];

  xssPatterns.forEach((pattern) => {
    let match;
    while ((match = pattern.regex.exec(line)) !== null) {
      vulnerabilities.push({
        type: pattern.type,
        line: lineIndex,
        column: match.index,
        endColumn: match.index + match[0].length,
        message: pattern.message,
        severity: pattern.severity,
      });
    }
    pattern.regex.lastIndex = 0;
  });
}
