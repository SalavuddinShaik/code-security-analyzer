import OpenAI from "openai";
import * as vscode from "vscode";
import { getComplianceMapping } from "./complianceMapping";

export class AIService {
  private openai: OpenAI | null = null;
  private cache: Map<string, string> = new Map();

  constructor() {
    this.initializeClient();
  }

  private initializeClient() {
    const config = vscode.workspace.getConfiguration("codeSecurityAnalyzer");
    const apiKey = config.get<string>("openaiApiKey");

    if (apiKey) {
      this.openai = new OpenAI({ apiKey });
    }
  }

  async getExplanation(
    vulnerabilityType: string,
    code: string
  ): Promise<string> {
    const cacheKey = `${vulnerabilityType}-${code}`;
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey)!;
    }

    const config = vscode.workspace.getConfiguration("codeSecurityAnalyzer");
    const aiEnabled = config.get<boolean>("enableAI", true);

    if (!aiEnabled || !this.openai) {
      return this.getFallbackExplanation(vulnerabilityType);
    }

    try {
      const complianceInfo = getComplianceMapping(vulnerabilityType);
      let complianceContext = "";

      if (complianceInfo) {
        complianceContext = `\n\nCOMPLIANCE IMPACT:
This affects: ${complianceInfo.safeguards.join(", ")}
Risk Level: ${complianceInfo.riskLevel}
Standards: ${complianceInfo.sectionReferences[0] || "Multiple"}`;
      }

      const response = await this.openai.chat.completions.create({
        model: "gpt-3.5-turbo",
        messages: [
          {
            role: "system",
            content: `You are a security expert teaching developers. Be concise and practical. Always include a code example showing the fix.`,
          },
          {
            role: "user",
            content: `Explain this ${vulnerabilityType} vulnerability:

CODE: ${code}${complianceContext}

Provide exactly 3 points:

1. Risk: What's dangerous about this (1-2 sentences)

2. Fix: Show a concrete code example of how to fix it

3. Importance: Why this matters for security (1-2 sentences)

Keep it under 200 words. Be specific and educational.`,
          },
        ],
        max_tokens: 300,
        temperature: 0.7,
      });

      const explanation =
        response.choices[0]?.message?.content ||
        this.getFallbackExplanation(vulnerabilityType);

      this.cache.set(cacheKey, explanation);

      return explanation;
    } catch (error) {
      console.error("AI Service Error:", error);
      return this.getFallbackExplanation(vulnerabilityType);
    }
  }

  private getFallbackExplanation(vulnerabilityType: string): string {
    const categoryMap: Record<string, string> = {
      "hardcoded-api-key": "hardcoded-secret",
      "hardcoded-password": "hardcoded-secret",
      "hardcoded-secret": "hardcoded-secret",
      "hardcoded-jwt": "hardcoded-secret",
      "hardcoded-encryption-key": "weak-crypto",
      "sql-injection-concat": "sql-injection",
      "sql-injection-insert": "sql-injection",
      "sql-injection-update": "sql-injection",
      "sql-injection-delete": "sql-injection",
      "sql-injection-query": "sql-injection",
      "sql-injection-template": "sql-injection",
      "xss-innerHTML": "xss",
      "xss-document-write": "xss",
      "xss-jquery-html": "xss",
      "xss-outerHTML": "xss",
      "code-injection-eval": "code-injection",
      "sensitive-data-logging": "sensitive-data-logging",
      "insecure-storage": "insecure-storage",
      "weak-random": "weak-random",
      "weak-random-number": "weak-random",
      "weak-random-generation": "weak-random",
      "weak-hash-algorithm": "weak-crypto",
      "weak-encryption": "weak-crypto",
      "insecure-http": "insecure-http",
      "http-url-config": "insecure-http",
      "debug-flag-enabled": "debug-mode",
      "debug-console-usage": "debug-mode",
      "command-injection": "command-injection",
      "command-injection-template": "command-injection",
      "path-traversal": "path-traversal",
      "relative-path-usage": "path-traversal",
    };

    const category = categoryMap[vulnerabilityType] || "generic";

    const complianceInfo = getComplianceMapping(category);
    let complianceSection = "";

    if (complianceInfo) {
      complianceSection = `\n\n⚡ Compliance Impact: ${
        complianceInfo.riskLevel
      } Risk\nAffects: ${complianceInfo.safeguards[0]}\nStandard: ${
        complianceInfo.sectionReferences[0] || "Multiple"
      }`;
    }

    const fallbacks: Record<string, string> = {
      "hardcoded-secret": `Security Issue: Hardcoded Credentials

1. Risk: Hardcoded credentials in source code are visible to anyone with repository access, including in version control history.

2. Fix: Move secrets to environment variables:
   Before: const apiKey = "sk-123..."
   After: const apiKey = process.env.API_KEY

3. Importance: Exposed credentials can lead to unauthorized access, data breaches, and account compromise.${complianceSection}

💡 Configure OpenAI API key for detailed AI-powered explanations.`,

      "sql-injection": `Security Issue: SQL Injection Vulnerability

1. Risk: String concatenation in SQL allows attackers to inject malicious SQL commands, potentially accessing or deleting your entire database.

2. Fix: Use parameterized queries:
   Before: db.query("SELECT * FROM users WHERE id = " + userId)
   After: db.query("SELECT * FROM users WHERE id = $1", [userId])

3. Importance: SQL injection can result in complete database compromise, data theft, and deletion.${complianceSection}

💡 Configure OpenAI API key for detailed AI-powered explanations.`,

      xss: `Security Issue: Cross-Site Scripting (XSS)

1. Risk: Unsanitized HTML enables attackers to inject malicious scripts that steal user data or hijack sessions.

2. Fix: Use textContent or sanitize HTML:
   Before: element.innerHTML = userInput
   After: element.textContent = userInput
   Or: element.innerHTML = DOMPurify.sanitize(userInput)

3. Importance: XSS attacks can steal cookies, session tokens, and sensitive user data.${complianceSection}

💡 Configure OpenAI API key for detailed AI-powered explanations.`,

      "code-injection": `Security Issue: Code Injection via eval()

1. Risk: eval() executes arbitrary code strings, allowing attackers to run malicious code in your application.

2. Fix: Use safe alternatives:
   Before: eval(userInput)
   After: JSON.parse(userInput)
   Or: Avoid eval() entirely

3. Importance: Code injection can lead to complete application compromise and server takeover.${complianceSection}

💡 Configure OpenAI API key for detailed AI-powered explanations.`,

      "sensitive-data-logging": `Security Issue: Sensitive Data in Logs

1. Risk: Logging sensitive data exposes credentials in console logs and log files accessible to developers and attackers.

2. Fix: Remove or redact sensitive data:
   Before: console.log("Password:", password)
   After: console.log("Login attempt for user:", username)

3. Importance: Logs are often stored unencrypted and accessible to many systems.${complianceSection}

💡 Configure OpenAI API key for detailed AI-powered explanations.`,

      "insecure-storage": `Security Issue: Insecure Browser Storage

1. Risk: localStorage and sessionStorage are unencrypted and accessible to any JavaScript, including malicious scripts.

2. Fix: Use secure alternatives:
   Before: localStorage.setItem('token', authToken)
   After: Use HTTP-only secure cookies
   Or: Store tokens in memory only

3. Importance: Stored tokens can be stolen via XSS attacks, leading to account takeover.${complianceSection}

💡 Configure OpenAI API key for detailed AI-powered explanations.`,

      "weak-random": `Security Issue: Weak Random Number Generation

1. Risk: Math.random() is predictable and not cryptographically secure.

2. Fix: Use crypto APIs:
   Before: const token = Math.random() * 1000000
   After: const token = crypto.randomBytes(32).toString('hex')

3. Importance: Weak randomness undermines session tokens and password resets.${complianceSection}

💡 Configure OpenAI API key for detailed AI-powered explanations.`,

      "weak-crypto": `Security Issue: Weak Cryptographic Algorithm

1. Risk: MD5, SHA1, and DES are cryptographically broken.

2. Fix: Use secure algorithms:
   Before: crypto.createHash('md5')
   After: crypto.createHash('sha256')

3. Importance: Weak encryption fails to protect sensitive data.${complianceSection}

💡 Configure OpenAI API key for detailed AI-powered explanations.`,

      "insecure-http": `Security Issue: Unencrypted HTTP Connection

1. Risk: HTTP transmits data in plaintext.

2. Fix: Always use HTTPS:
   Before: fetch('http://api.example.com/data')
   After: fetch('https://api.example.com/data')

3. Importance: Unencrypted connections expose all data to network attackers.${complianceSection}

💡 Configure OpenAI API key for detailed AI-powered explanations.`,

      "debug-mode": `Security Issue: Debug Mode Enabled

1. Risk: Debug mode exposes internal details and stack traces.

2. Fix: Disable debug in production:
   Before: const DEBUG = true
   After: const DEBUG = process.env.NODE_ENV !== 'production'

3. Importance: Debug information disclosure aids attackers.${complianceSection}

💡 Configure OpenAI API key for detailed AI-powered explanations.`,

      "command-injection": `Security Issue: Command Injection

1. Risk: Concatenating user input into shell commands allows attacker-controlled execution.

2. Fix: Use safe alternatives:
   Before: exec('ls ' + userInput)
   After: execFile('ls', [sanitizedPath])

3. Importance: Command injection can lead to full server compromise.${complianceSection}

💡 Configure OpenAI API key for detailed AI-powered explanations.`,

      "path-traversal": `Security Issue: Path Traversal

1. Risk: Unsanitized file paths allow access to files outside intended directories.

2. Fix: Sanitize paths:
   Before: fs.readFile('./uploads/' + filename)
   After: const safe = path.join(__dirname, 'uploads', path.basename(filename))

3. Importance: Path traversal can expose sensitive configuration files.${complianceSection}

💡 Configure OpenAI API key for detailed AI-powered explanations.`,

      generic: `Security Vulnerability Detected

Configure OpenAI API key in settings for detailed security explanations and fix recommendations.

Settings → Extensions → Code Security Analyzer → OpenAI API Key`,
    };

    return fallbacks[category] || fallbacks["generic"];
  }

  public clearCache() {
    this.cache.clear();
  }
}
