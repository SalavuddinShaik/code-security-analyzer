import * as vscode from "vscode";

export interface Vulnerability {
  type: string;
  line: number;
  column: number;
  endColumn: number;
  message: string;
  severity: vscode.DiagnosticSeverity;

const COMPILED_PATTERNS = {
  secrets: [
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
  ],
  sql: [
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
  ],
  xss: [
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
  ],
  insecure: [
    {
      regex:
        /console\.log\s*\(\s*[^)]*(?:password|token|secret|key|auth)[^)]*\)/gi,
      type: "sensitive-data-logging",
      message: "Logging sensitive data - remove console.log with credentials",
      severity: vscode.DiagnosticSeverity.Warning,
    },
    {
      regex:
        /(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"`][^'"`]*(?:password|token|auth)[^'"`]*['"`]/gi,
      type: "insecure-storage",
      message:
        "Storing sensitive data in browser storage - use secure alternatives",
      severity: vscode.DiagnosticSeverity.Error,
    },
    {
      regex: /fetch\s*\(\s*['"`][^'"`]*\?[^'"`]*(?:password|token)=/gi,
      type: "credentials-in-url",
      message: "Sending credentials in URL - use POST body or headers instead",
      severity: vscode.DiagnosticSeverity.Error,
    },
    {
      regex: /Math\.random\s*\(\s*\)[^;]*(?:token|session|id|key)/gi,
      type: "weak-random",
      message:
        "Using Math.random() for security - use crypto.getRandomValues() instead",
      severity: vscode.DiagnosticSeverity.Warning,
    },
  ],
  weakRandom: [
    {
      regex: /Math\.random\s*\(\s*\)\s*\*\s*\d+/gi,
      type: "weak-random-number",
      message:
        "Math.random() is not cryptographically secure - use crypto.randomInt() for security operations",
      severity: vscode.DiagnosticSeverity.Error,
    },
    {
      regex: /Math\.floor\s*\(\s*Math\.random\s*\(\s*\)/gi,
      type: "weak-random-generation",
      message:
        "Using Math.random() for number generation - use crypto for security-sensitive values",
      severity: vscode.DiagnosticSeverity.Error,
    },
  ],
  
  crypto: [
    {
      regex: /crypto\.createHash\s*\(\s*['"`](md5|sha1)['"`]\s*\)/gi,
      type: "weak-hash-algorithm",
      message:
        "Weak hash algorithm detected - use SHA-256 or stronger instead of MD5/SHA1",
      severity: vscode.DiagnosticSeverity.Error,
    },
    {
      regex: /crypto\.createCipher\s*\(\s*['"`](des|3des|rc4|rc2)['"`]/gi,
      type: "weak-encryption",
      message:
        "Weak encryption algorithm - use AES-256-GCM or ChaCha20 instead",
      severity: vscode.DiagnosticSeverity.Error,
    },
    {
      regex:
        /(?:encryptionKey|cryptoKey|cipherKey)\s*[:=]\s*['"`]([^'"`]{8,})['"`]/gi,
      type: "hardcoded-encryption-key",
      message:
        "Hardcoded encryption key detected - use secure key management service",
      severity: vscode.DiagnosticSeverity.Error,
    },
  ],
  insecureHttp: [
    {
      regex:
        /(?:fetch|axios\.get|axios\.post|request)\s*\(\s*['"`]http:\/\/[^'"`]+['"`]/gi,
      type: "insecure-http",
      message: "Insecure HTTP connection - use HTTPS for data transmission",
      severity: vscode.DiagnosticSeverity.Warning,
    },
    {
      regex:
        /(?:apiUrl|endpoint|baseUrl)\s*[:=]\s*['"`]http:\/\/[^'"`]+['"`]/gi,
      type: "http-url-config",
      message:
        "HTTP URL in configuration - should use HTTPS for secure communication",
      severity: vscode.DiagnosticSeverity.Warning,
    },
  ],
  debugMode: [
    {
      regex: /(?:DEBUG|DEVELOPMENT|DEV_MODE)\s*[:=]\s*true/gi,
      type: "debug-flag-enabled",
      message:
        "Debug flag enabled - disable in production to prevent information disclosure",
      severity: vscode.DiagnosticSeverity.Warning,
    },
    {
      regex: /console\.(?:debug|trace)\s*\(/gi,
      type: "debug-console-usage",
      message: "Debug console usage - remove before production deployment",
      severity: vscode.DiagnosticSeverity.Warning,
    },
  ],
  commandInjection: [
    {
      regex: /(?:exec|spawn|execSync|spawnSync)\s*\(\s*[^)]*\+[^)]*\)/gi,
      type: "command-injection",
      message:
        "Potential command injection - avoid string concatenation in shell commands",
      severity: vscode.DiagnosticSeverity.Error,
    },
    {
      regex: /(?:exec|spawn)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`\s*\)/gi,
      type: "command-injection-template",
      message: "Command injection via template literals - sanitize user input",
      severity: vscode.DiagnosticSeverity.Error,
    },
  ],
  pathTraversal: [
    {
      regex: /(?:readFile|writeFile|unlink|stat)\s*\([^)]*\+[^)]*\)/gi,
      type: "path-traversal",
      message: "Potential path traversal - validate and sanitize file paths",
      severity: vscode.DiagnosticSeverity.Error,
    },
    {
      regex: /(?:\.\.\/|\.\.\\)/gi,
      type: "relative-path-usage",
      message:
        "Relative path detected - may enable directory traversal attacks",
      severity: vscode.DiagnosticSeverity.Warning,
    },
  ],
};

// main detection function - checks all vulnerability types
export function detectVulnerabilities(text: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  const lines = text.split("\n");

  // ✅ WEEK 9 OPTIMIZATION: Use for loop instead of forEach (slightly faster)
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];

    // ✅ WEEK 9 OPTIMIZATION: Skip empty lines and comments
    const trimmedLine = line.trim();
    if (
      trimmedLine.length === 0 ||
      trimmedLine.startsWith("//") ||
      trimmedLine.startsWith("/*")
    ) {
      continue;
    }

    // Week 1-10 patterns
    detectHardcodedSecrets(line, lineIndex, vulnerabilities);
    detectSQLInjection(line, lineIndex, vulnerabilities);
    detectXSSVulnerabilities(line, lineIndex, vulnerabilities);
    detectInsecurePatterns(line, lineIndex, vulnerabilities);
    detectWeakRandom(line, lineIndex, vulnerabilities);

    // ✅ WEEK 11: New patterns
    detectWeakCryptography(line, lineIndex, vulnerabilities);
    detectInsecureHttp(line, lineIndex, vulnerabilities);
    detectDebugMode(line, lineIndex, vulnerabilities);
    detectCommandInjection(line, lineIndex, vulnerabilities);
    detectPathTraversal(line, lineIndex, vulnerabilities);
  }

  return vulnerabilities;
}


function detectPatterns(
  line: string,
  lineIndex: number,
  patterns: Array<{
    regex: RegExp;
    type: string;
    message: string;
    severity: vscode.DiagnosticSeverity;
  }>,
  vulnerabilities: Vulnerability[]
) {
  for (const pattern of patterns) {
    let match;
    // Reset regex lastIndex before each use
    pattern.regex.lastIndex = 0;

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
    // Reset again after loop
    pattern.regex.lastIndex = 0;
  }
}

// detect hardcoded credentials, API keys, passwords, etc.
function detectHardcodedSecrets(
  line: string,
  lineIndex: number,
  vulnerabilities: Vulnerability[]
) {
  detectPatterns(line, lineIndex, COMPILED_PATTERNS.secrets, vulnerabilities);
}

// detect SQL injection vulnerabilities
function detectSQLInjection(
  line: string,
  lineIndex: number,
  vulnerabilities: Vulnerability[]
) {
  detectPatterns(line, lineIndex, COMPILED_PATTERNS.sql, vulnerabilities);
}

// detect XSS and code injection vulnerabilities
function detectXSSVulnerabilities(
  line: string,
  lineIndex: number,
  vulnerabilities: Vulnerability[]
) {
  detectPatterns(line, lineIndex, COMPILED_PATTERNS.xss, vulnerabilities);
}

// detect insecure patterns like logging sensitive data
function detectInsecurePatterns(
  line: string,
  lineIndex: number,
  vulnerabilities: Vulnerability[]
) {
  detectPatterns(line, lineIndex, COMPILED_PATTERNS.insecure, vulnerabilities);
}

// detect weak random number generation
function detectWeakRandom(
  line: string,
  lineIndex: number,
  vulnerabilities: Vulnerability[]
) {
  detectPatterns(
    line,
    lineIndex,
    COMPILED_PATTERNS.weakRandom,
    vulnerabilities
  );
}

function detectWeakCryptography(
  line: string,
  lineIndex: number,
  vulnerabilities: Vulnerability[]
) {
  detectPatterns(line, lineIndex, COMPILED_PATTERNS.crypto, vulnerabilities);
}


function detectInsecureHttp(
  line: string,
  lineIndex: number,
  vulnerabilities: Vulnerability[]
) {
  detectPatterns(
    line,
    lineIndex,
    COMPILED_PATTERNS.insecureHttp,
    vulnerabilities
  );
}

// ✅ WEEK 11: detect debug mode
function detectDebugMode(
  line: string,
  lineIndex: number,
  vulnerabilities: Vulnerability[]
) {
  detectPatterns(line, lineIndex, COMPILED_PATTERNS.debugMode, vulnerabilities);
}

// ✅ WEEK 11: detect command injection
function detectCommandInjection(
  line: string,
  lineIndex: number,
  vulnerabilities: Vulnerability[]
) {
  detectPatterns(
    line,
    lineIndex,
    COMPILED_PATTERNS.commandInjection,
    vulnerabilities
  );
}

// ✅ WEEK 11: detect path traversal
function detectPathTraversal(
  line: string,
  lineIndex: number,
  vulnerabilities: Vulnerability[]
) {
  detectPatterns(
    line,
    lineIndex,
    COMPILED_PATTERNS.pathTraversal,
    vulnerabilities
  );
}
