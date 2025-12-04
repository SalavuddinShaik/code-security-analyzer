import * as vscode from "vscode";
import { detectVulnerabilities } from "./detector";
import { AIService } from "./aiService";
import { SecurityDashboardPanel } from "./webview";
import { ReportGenerator } from "./reportGenerator";

export function activate(context: vscode.ExtensionContext) {
  console.log("Code Security Analyzer is now active!");

  const aiService = new AIService();

  // check if user has configured API key
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

     
      const lineCount = document.lineCount;
      if (lineCount > 10000) {
        vscode.window.showWarningMessage(
          `File is very large (${lineCount} lines). Security scanning may be slower.`
        );
      }

      const vulnerabilities = detectVulnerabilities(text);

      const diagnostics: vscode.Diagnostic[] = [];

      // ✅ WEEK 9 OPTIMIZATION #3: Remove await loop - create diagnostics synchronously
      for (const vuln of vulnerabilities) {
        const range = new vscode.Range(
          new vscode.Position(vuln.line, vuln.column),
          new vscode.Position(vuln.line, vuln.endColumn)
        );

        const codeSnippet = text.substring(
          document.offsetAt(range.start),
          document.offsetAt(range.end)
        );

        // ✅ Don't await - use basic message immediately
        const basicMessage = vuln.message;

        const diagnostic = new vscode.Diagnostic(
          range,
          basicMessage,
          vuln.severity
        );
        diagnostic.code = vuln.type;
        diagnostic.source = "Code Security Analyzer";

        // ✅ Store code snippet for later AI explanation
        (diagnostic as any).codeSnippet = codeSnippet;

        diagnostics.push(diagnostic);
      }

      diagnosticCollection.set(document.uri, diagnostics);
    }
  }

  // hover provider for AI explanations
  context.subscriptions.push(
    vscode.languages.registerHoverProvider(["javascript", "typescript"], {
      async provideHover(document, position, token) {
        const diagnostics = diagnosticCollection.get(document.uri);
        if (!diagnostics) return;

        // Find diagnostic at cursor position
        const diagnostic = diagnostics.find((d) => d.range.contains(position));
        if (!diagnostic || !diagnostic.code) return;

        const codeSnippet = (diagnostic as any).codeSnippet || "";

        //Fetch AI explanation on-demand
        const aiExplanation = await aiService.getExplanation(
          diagnostic.code as string,
          codeSnippet
        );

        const markdown = new vscode.MarkdownString();
        markdown.appendMarkdown(
          `**Security Issue:** ${diagnostic.message}\n\n`
        );
        markdown.appendMarkdown(`**AI Security Expert:**\n\n${aiExplanation}`);
        markdown.isTrusted = true;

        return new vscode.Hover(markdown);
      },
    })
  );

  // scan active file on startup
  if (vscode.window.activeTextEditor) {
    updateDiagnostics(vscode.window.activeTextEditor.document);
  }

  // scan when switching between files
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) {
        updateDiagnostics(editor.document);
      }
    })
  );

  // ✅ WEEK 9 OPTIMIZATION #5: Increase debounce to 1000ms (from 500ms)
  // Reduces unnecessary scans while typing
  let timeout: NodeJS.Timeout | undefined;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (timeout) {
        clearTimeout(timeout);
      }
      timeout = setTimeout(() => {
        updateDiagnostics(e.document);
      }, 1000); // ✅ Changed from 500ms to 1000ms
    })
  );

  // manual scan command
  context.subscriptions.push(
    vscode.commands.registerCommand("code-security-analyzer.scanFile", () => {
      if (vscode.window.activeTextEditor) {
        updateDiagnostics(vscode.window.activeTextEditor.document);
        vscode.window.showInformationMessage("Security scan completed!");
      }
    })
  );

  // dashboard command
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "code-security-analyzer.showDashboard",
      () => {
        const panel = SecurityDashboardPanel.createOrShow(context.extensionUri);

        if (vscode.window.activeTextEditor) {
          const document = vscode.window.activeTextEditor.document;
          const text = document.getText();
          const vulnerabilities = detectVulnerabilities(text);
          panel.updateVulnerabilities(vulnerabilities);
        }
      }
    )
  );

  // ✅ WEEK 9 OPTIMIZATION #6: Add error handling to export
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "code-security-analyzer.exportReport",
      async () => {
        try {
          const editor = vscode.window.activeTextEditor;
          if (!editor) {
            vscode.window.showErrorMessage("No active file to analyze");
            return;
          }

          const document = editor.document;
          const text = document.getText();
          const vulnerabilities = detectVulnerabilities(text);

          if (vulnerabilities.length === 0) {
            vscode.window.showInformationMessage(
              "No vulnerabilities found! Your code looks secure."
            );
            return;
          }

          const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
          const projectName = workspaceFolder?.name || "Unknown Project";
          const fileName = document.fileName.split("/").pop() || "unknown.js";

          const reportGenerator = new ReportGenerator();
          const report = reportGenerator.generateReport(
            vulnerabilities,
            fileName,
            projectName
          );
          const html = reportGenerator.generateHTML(report);

          const saveUri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file(
              `${
                workspaceFolder?.uri.fsPath || require("os").homedir()
              }/security-report-${Date.now()}.html`
            ),
            filters: {
              "HTML Files": ["html"],
            },
          });

          if (saveUri) {
            const fs = require("fs");
            fs.writeFileSync(saveUri.fsPath, html, "utf8");

            vscode.window
              .showInformationMessage(
                "Security report exported successfully",
                "Open Report"
              )
              .then((selection) => {
                if (selection === "Open Report") {
                  vscode.env.openExternal(saveUri);
                }
              });
          }
        } catch (error) {
          console.error("Export error:", error);
          vscode.window.showErrorMessage(
            `Failed to export report: ${
              error instanceof Error ? error.message : "Unknown error"
            }`
          );
        }
      }
    )
  );
}

export function deactivate() {}
