import * as vscode from 'vscode';
import { detectVulnerabilities } from './detector';

export function activate(context: vscode.ExtensionContext) {
    console.log('AI Security Assistant is now active!');

    // Create diagnostic collection for showing security issues
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('security');
    context.subscriptions.push(diagnosticCollection);

    // Function to analyze document for vulnerabilities
    function updateDiagnostics(document: vscode.TextDocument) {
        if (document.languageId === 'javascript' || document.languageId === 'typescript') {
            const text = document.getText();
            const vulnerabilities = detectVulnerabilities(text);
            
            const diagnostics = vulnerabilities.map(vuln => {
                const range = new vscode.Range(
                    new vscode.Position(vuln.line, vuln.column),
                    new vscode.Position(vuln.line, vuln.endColumn)
                );
                return new vscode.Diagnostic(range, vuln.message, vuln.severity);
            });
            
            diagnosticCollection.set(document.uri, diagnostics);
        }
    }

    // Analyze active editor on startup
    if (vscode.window.activeTextEditor) {
        updateDiagnostics(vscode.window.activeTextEditor.document);
    }

    // Listen for active editor changes
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor) {
                updateDiagnostics(editor.document);
            }
        })
    );

    // Listen for document changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(e => {
            updateDiagnostics(e.document);
        })
    );
}

export function deactivate() {}