import OpenAI from "openai";
import * as vscode from "vscode";

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
    // Check cache first
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
      const response = await this.openai.chat.completions.create({
        model: "gpt-3.5-turbo",
        messages: [
          {
            role: "system",
            content:
              "You are a security expert explaining vulnerabilities to developers. Be concise and educational.",
          },
          {
            role: "user",
            content: `Explain this ${vulnerabilityType} vulnerability in the code:\n${code}\n\nProvide: 1) What the risk is, 2) How to fix it, 3) Why it matters.`,
          },
        ],
        max_tokens: 200,
        temperature: 0.7,
      });

      const explanation =
        response.choices[0]?.message?.content ||
        this.getFallbackExplanation(vulnerabilityType);

      // Cache the response
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
    };

    const category = categoryMap[vulnerabilityType] || "generic";

    const fallbacks: Record<string, string> = {
      "hardcoded-secret":
        "Hardcoded credentials in source code are visible to anyone with repository access. Move secrets to environment variables or secure vault services.\n\nConfigure OpenAI API key for detailed AI-powered explanations.",
      "sql-injection":
        "String concatenation in SQL queries allows attackers to manipulate your database. Always use parameterized queries or prepared statements.\n\nConfigure OpenAI API key for detailed AI-powered explanations.",
      xss: "Unsanitized dynamic HTML enables script injection attacks. Use textContent for text or sanitize HTML with DOMPurify library.\n\nConfigure OpenAI API key for detailed AI-powered explanations.",
      "code-injection":
        "eval() executes arbitrary code and is extremely dangerous. Use JSON.parse() for data or find safer alternatives.\n\nConfigure OpenAI API key for detailed AI-powered explanations.",
      generic:
        "Configure OpenAI API key in settings for AI-powered security explanations and remediation guidance.",
    };

    return fallbacks[category] || fallbacks["generic"];
  }

  public clearCache() {
    this.cache.clear();
  }
}
