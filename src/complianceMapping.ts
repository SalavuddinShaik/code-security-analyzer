export interface ComplianceMapping {
  vulnerabilityType: string;
  safeguards: string[];
  sectionReferences: string[];
  riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  complianceRequirements: string[];
  remediationSteps: string[];
  potentialImpact: string;
}

// Security compliance mapping for each vulnerability type
// Based on industry standards including HIPAA, GDPR, PCI-DSS, and OWASP
export const complianceMap: Record<string, ComplianceMapping> = {
  "hardcoded-secret": {
    vulnerabilityType: "Hardcoded Secrets (API Keys, Passwords, Tokens)",
    safeguards: ["Access Control", "Transmission Security"],
    sectionReferences: [
      "OWASP A07:2021 - Identification and Authentication Failures",
      "CWE-798 - Use of Hard-coded Credentials",
      "NIST 800-53 - IA-5 Authenticator Management",
    ],
    riskLevel: "HIGH",
    complianceRequirements: [
      "Implement unique user identification for each person or entity",
      "Ensure that credentials are not embedded in source code",
      "Use secure credential storage mechanisms",
      "Encrypt credentials both in transit and at rest",
      "Implement proper key management and rotation procedures",
    ],
    remediationSteps: [
      "Remove all hardcoded credentials from source code immediately",
      "Move credentials to environment variables",
      "Use secure secret management systems like AWS Secrets Manager or Azure Key Vault",
      "Implement credential rotation policies",
      "Never commit credentials to version control systems",
      "Use gitignore to exclude sensitive configuration files",
      "Conduct code review to identify any remaining hardcoded secrets",
    ],
    potentialImpact: "Unauthorized access to systems and data",
  },

  "sql-injection": {
    vulnerabilityType: "SQL Injection",
    safeguards: ["Access Control", "Integrity Controls", "Audit Controls"],
    sectionReferences: [
      "OWASP A03:2021 - Injection",
      "CWE-89 - SQL Injection",
      "PCI DSS 6.5.1 - Injection Flaws",
    ],
    riskLevel: "CRITICAL",
    complianceRequirements: [
      "Implement mechanisms to protect data from unauthorized access",
      "Ensure the integrity of data and prevent improper alteration or destruction",
      "Maintain audit trails that cannot be tampered with",
      "Apply the principle of least privilege to database accounts",
      "Validate that data has not been improperly altered or destroyed",
    ],
    remediationSteps: [
      "Use parameterized queries or prepared statements for all database operations",
      "Implement input validation and sanitization on all user inputs",
      "Use ORM frameworks with built-in SQL injection protection",
      "Apply the principle of least privilege for database accounts",
      "Implement Web Application Firewall to detect and block SQL injection attempts",
      "Conduct regular security testing including SQL injection vulnerability scans",
      "Enable database query logging and monitoring for suspicious activity",
    ],
    potentialImpact:
      "Data breach, data loss, or unauthorized data modification",
  },

  xss: {
    vulnerabilityType: "Cross-Site Scripting (XSS)",
    safeguards: [
      "Access Control",
      "Transmission Security",
      "Integrity Controls",
    ],
    sectionReferences: [
      "OWASP A03:2021 - Injection",
      "CWE-79 - Cross-site Scripting",
      "PCI DSS 6.5.7 - Cross-site Scripting",
    ],
    riskLevel: "HIGH",
    complianceRequirements: [
      "Prevent session hijacking and unauthorized access to sensitive data",
      "Protect against unauthorized interception or modification of data during transmission",
      "Ensure user authentication mechanisms cannot be compromised",
      "Maintain the confidentiality and integrity of user data",
    ],
    remediationSteps: [
      "Sanitize and escape all user inputs before rendering in HTML",
      "Implement Content Security Policy headers to restrict script execution",
      "Use HTTP-only and Secure flags for all session cookies",
      "Encode output data properly based on context",
      "Use modern frameworks with built-in XSS protection",
      "Validate input on both client-side and server-side",
      "Implement strict output encoding libraries",
      "Regular security testing for XSS vulnerabilities",
    ],
    potentialImpact:
      "Session hijacking, data theft, or malicious code execution",
  },

  "insecure-storage": {
    vulnerabilityType: "Insecure Local Storage of Sensitive Data",
    safeguards: ["Access Control", "Encryption and Decryption"],
    sectionReferences: [
      "OWASP A02:2021 - Cryptographic Failures",
      "CWE-922 - Insecure Storage of Sensitive Information",
      "PCI DSS 3.4 - Protection of Cardholder Data",
    ],
    riskLevel: "CRITICAL",
    complianceRequirements: [
      "Encrypt sensitive data at rest as required by security standards",
      "Implement proper access controls to prevent unauthorized local access to data",
      "Ensure data confidentiality is maintained",
      "Prevent unauthorized viewing or copying of sensitive data stored locally",
    ],
    remediationSteps: [
      "Never store sensitive data in localStorage or sessionStorage as these are not encrypted",
      "Use encrypted storage mechanisms for any sensitive data",
      "Implement server-side session management instead of client-side storage",
      "Use secure, HTTP-only, and encrypted cookies for session tokens only",
      "Implement automatic data expiration and cleanup",
      "If temporary client-side storage is absolutely necessary, use encryption before storage",
      "Conduct regular audits of data storage practices",
      "Educate developers on secure data storage requirements",
    ],
    potentialImpact: "Exposure of sensitive user or business data",
  },

  "weak-random": {
    vulnerabilityType: "Weak Random Number Generation",
    safeguards: ["Access Control", "Encryption and Decryption"],
    sectionReferences: [
      "OWASP A02:2021 - Cryptographic Failures",
      "CWE-330 - Use of Insufficiently Random Values",
      "NIST 800-53 - SC-13 Cryptographic Protection",
    ],
    riskLevel: "MEDIUM",
    complianceRequirements: [
      "Generate unpredictable session tokens and identifiers",
      "Create strong encryption keys that cannot be easily guessed",
      "Ensure cryptographic security for all authentication mechanisms",
      "Prevent token prediction attacks that could lead to unauthorized access",
    ],
    remediationSteps: [
      "Replace Math.random() with crypto.randomBytes() in Node.js",
      "Use crypto.getRandomValues() in browser environments",
      "Implement cryptographically secure random number generators",
      "Generate session tokens with at least 128 bits of entropy",
      "Use established libraries for token generation",
      "Implement proper key derivation functions for password hashing",
      "Never use predictable seed values for random number generation",
      "Conduct security review of all random number usage in authentication and encryption",
    ],
    potentialImpact: "Predictable tokens leading to unauthorized access",
  },

  "sensitive-data-logging": {
    vulnerabilityType:
      "Sensitive Data Logging (Passwords, Tokens, Personal Data)",
    safeguards: ["Access Control", "Audit Controls", "Transmission Security"],
    sectionReferences: [
      "OWASP A09:2021 - Security Logging and Monitoring Failures",
      "CWE-532 - Information Exposure Through Log Files",
      "GDPR Article 32 - Security of Processing",
    ],
    riskLevel: "HIGH",
    complianceRequirements: [
      "Protect sensitive data from unauthorized disclosure in logs and console output",
      "Maintain secure audit trails that do not contain sensitive data",
      "Prevent exposure of authentication credentials and tokens",
      "Implement proper logging practices that maintain security while enabling debugging",
      "Ensure log files are properly secured and access-controlled",
    ],
    remediationSteps: [
      "Never log passwords, authentication tokens, or session IDs",
      "Implement log sanitization to automatically remove sensitive data patterns",
      "Use structured logging with sensitivity levels",
      "Redact or mask sensitive data before logging",
      "Implement secure log storage with encryption and access controls",
      "Review and sanitize all error messages to prevent information disclosure",
      "Use logging frameworks with built-in data masking capabilities",
      "Remove or disable verbose logging in production environments",
      "Conduct regular log audits to ensure no sensitive data is being logged",
      "Train developers on secure logging practices",
    ],
    potentialImpact: "Exposure of sensitive data through log files",
  },
};

export function getComplianceMapping(
  vulnerabilityType: string
): ComplianceMapping | undefined {
  return complianceMap[vulnerabilityType];
}

export function generateComplianceSummary(vulnerabilities: string[]): string {
  const affectedSafeguards = new Set<string>();
  const safeguardCount: Record<string, number> = {};

  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  vulnerabilities.forEach((vuln) => {
    const mapping = complianceMap[vuln];
    if (mapping) {
      switch (mapping.riskLevel) {
        case "CRITICAL":
          criticalCount++;
          break;
        case "HIGH":
          highCount++;
          break;
        case "MEDIUM":
          mediumCount++;
          break;
        case "LOW":
          lowCount++;
          break;
      }

      mapping.safeguards.forEach((safeguard) => {
        affectedSafeguards.add(safeguard);
        safeguardCount[safeguard] = (safeguardCount[safeguard] || 0) + 1;
      });
    }
  });

  const complianceStatus =
    criticalCount > 0 || highCount > 0 ? "AT RISK" : "SECURE";
  const totalViolations = criticalCount + highCount + mediumCount + lowCount;

  let summary = `
SECURITY COMPLIANCE ANALYSIS

VULNERABILITY SEVERITY BREAKDOWN:
   Critical Issues: ${criticalCount}
   High Risk Issues: ${highCount}
   Medium Risk Issues: ${mediumCount}
   Low Risk Issues: ${lowCount}
   Total Issues: ${totalViolations}

SECURITY STATUS: ${complianceStatus}

AFFECTED SECURITY CONTROLS:
`;

  if (affectedSafeguards.size > 0) {
    Array.from(affectedSafeguards).forEach((safeguard) => {
      summary += `   ${safeguard} (${safeguardCount[safeguard]} issue${
        safeguardCount[safeguard] > 1 ? "s" : ""
      })\n`;
    });
  } else {
    summary += "   None - Code appears secure\n";
  }

  if (criticalCount > 0 || highCount > 0) {
    summary += `
RISK ASSESSMENT:
   This codebase contains ${criticalCount + highCount} CRITICAL/HIGH severity 
   security issues that should be addressed immediately.
   
POTENTIAL IMPACT:
   These vulnerabilities could lead to data breaches, unauthorized access,
   or compliance violations. Addressing them is critical for security.

RECOMMENDED ACTIONS:
   1. Address all CRITICAL and HIGH severity issues immediately
   2. Review detailed remediation steps for each vulnerability
   3. Implement security testing in CI/CD pipeline
   4. Conduct regular security training for development team
`;
  } else {
    summary += `
SECURITY NOTES:
   No critical security issues detected. Continue following 
   security best practices and conduct regular security audits.
`;
  }

  return summary.trim();
}

export function getAllSectionReferences(vulnerabilities: string[]): string[] {
  const sections = new Set<string>();

  vulnerabilities.forEach((vuln) => {
    const mapping = complianceMap[vuln];
    if (mapping) {
      mapping.sectionReferences.forEach((ref) => sections.add(ref));
    }
  });

  return Array.from(sections).sort();
}

export function getEstimatedImpact(vulnerabilities: string[]): string {
  if (vulnerabilities.length === 0) {
    return "No security issues detected";
  }

  const impacts = vulnerabilities
    .map((vuln) => complianceMap[vuln]?.potentialImpact)
    .filter((impact): impact is string => impact !== undefined);

  if (impacts.length === 0) {
    return "Security impact assessment unavailable";
  }

  return `${impacts.length} security issue${
    impacts.length > 1 ? "s" : ""
  } detected with potential for: ${impacts.slice(0, 3).join(", ")}`;
}
