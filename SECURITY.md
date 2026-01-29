# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

1. **GitHub Security Advisories** (Preferred)
   - Go to the [Security tab](https://github.com/realworldtech/wincertmanager/security/advisories) of this repository
   - Click "Report a vulnerability"
   - Provide details of the vulnerability

2. **Email**
   - Send details to the security contact at Real World Technology Solutions
   - Visit [rwts.com.au](https://rwts.com.au) for contact information

### What to Include

Please include the following information in your report:

- Type of vulnerability (e.g., credential exposure, command injection, path traversal)
- Location of the affected source code (file and line number if possible)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if available)
- Impact assessment and potential attack scenarios

### Response Timeline

- **Initial Response**: Within 72 hours of report submission
- **Status Update**: Within 7 days with assessment and remediation plan
- **Resolution**: Dependent on severity and complexity

### Severity Classification

| Severity | Description | Target Resolution |
|----------|-------------|-------------------|
| Critical | Remote code execution, credential theft | 24-48 hours |
| High | Privilege escalation, authentication bypass | 7 days |
| Medium | Information disclosure, denial of service | 30 days |
| Low | Minor issues, hardening recommendations | Next release |

## Security Best Practices for Users

### Credential Protection

- Store acme-dns credentials using the default DPAPI encryption (JsonFile method)
- Restrict read access to `%ProgramData%\WinCertManager\Config\` to administrators only
- If using webhook API keys, restrict access to `logging-config.json`

### Network Security

- Ensure outbound HTTPS (port 443) is allowed to:
  - `acme-v02.api.letsencrypt.org` (Let's Encrypt API)
  - `acmedns.realworld.net.au` (acme-dns server, if using)
- Consider IP allowlisting for webhook endpoints

### File System Security

- Deploy scripts to a protected location (e.g., `C:\Tools\wincertmanager`)
- Restrict write access to script directories to prevent tampering
- Monitor for unauthorized modifications to PowerShell scripts

### Monitoring

- Review Windows Event Log (Application, source: WinCertManager) for anomalies
- Set up alerts for certificate renewal failures
- Monitor scheduled task execution status

## Security Features

This toolkit implements several security measures:

- **DPAPI Encryption**: Credentials encrypted using Windows Data Protection API
- **Secure Credential Storage**: P/Invoke API for Windows Credential Manager (avoids command-line exposure)
- **Authenticode Verification**: win-acme binary signature validated before execution
- **Path Traversal Protection**: Configuration file paths validated against allowed directories
- **TLS 1.2 Enforcement**: All network communications use TLS 1.2 minimum
- **Event Logging**: Security-relevant events logged to Windows Event Log

## Security Review

A detailed security review is available in [docs/security-review.md](docs/security-review.md).

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities. Contributors who report valid security issues will be acknowledged (with permission) in release notes.
