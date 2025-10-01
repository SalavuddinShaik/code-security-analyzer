import * as vscode from "vscode";
import { detectVulnerabilities } from "./detector";
import { AIService } from "./aiService";

export function activate(context: vscode.ExtensionContext) {
  console.log("Code Security Analyzer is now active!");

  const aiService = new AIService();

  // Check if API key is configured
  const config = vscode.workspace.getConfiguration("codeSecurityAnalyzer");
  const apiKey = config.get<string>("openaiApiKey");

  if (!apiKey) {
    vscode.window
      .showWarningMessage(
        "Enable AI-powered security education with OpenAI API key for enhanced explanations",
        "Configure Now",
        "Use Basic Mode"
      )
      .then((selection) => {
        if (selection === "Configure Now") {
          vscode.commands.executeCommand(
            "workbench.action.openSettings",
            "codeSecurityAnalyzer.openaiApiKey"
          );
        }
      });
  }

  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection("security");
  context.subscriptions.push(diagnosticCollection);

  async function updateDiagnostics(document: vscode.TextDocument) {
    if (
      document.languageId === "javascript" ||
      document.languageId === "typescript"
    ) {
      const text = document.getText();
      const vulnerabilities = detectVulnerabilities(text);

      const diagnostics: vscode.Diagnostic[] = [];

      for (const vuln of vulnerabilities) {
        const range = new vscode.Range(
          new vscode.Position(vuln.line, vuln.column),
          new vscode.Position(vuln.line, vuln.endColumn)
        );

        const codeSnippet = text.substring(
          document.offsetAt(range.start),
          document.offsetAt(range.end)
        );
        const aiExplanation = await aiService.getExplanation(
          vuln.type,
          codeSnippet
        );

        const enhancedMessage = `${vuln.message}\n\nAI Security Expert:\n${aiExplanation}`;

        const diagnostic = new vscode.Diagnostic(
          range,
          enhancedMessage,
          vuln.severity
        );
        diagnostic.code = vuln.type;
        diagnostic.source = "Code Security Analyzer";
        diagnostics.push(diagnostic);
      }

      diagnosticCollection.set(document.uri, diagnostics);
    }
  }

  if (vscode.window.activeTextEditor) {
    updateDiagnostics(vscode.window.activeTextEditor.document);
  }

  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) {
        updateDiagnostics(editor.document);
      }
    })
  );

  let timeout: NodeJS.Timeout | undefined;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (timeout) {
        clearTimeout(timeout);
      }
      timeout = setTimeout(() => {
        updateDiagnostics(e.document);
      }, 500);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("code-security-analyzer.scanFile", () => {
      if (vscode.window.activeTextEditor) {
        updateDiagnostics(vscode.window.activeTextEditor.document);
        vscode.window.showInformationMessage("Security scan completed!");
      }
    })
  );
}

export function deactivate() {}
