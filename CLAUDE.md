# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Windows Certificate Manager Toolkit - PowerShell scripts for automating SSL certificate management on Windows Server (2012+) using Let's Encrypt via win-acme. Supports IIS, RD Gateway, and LDAPS certificates.

## Linting

```powershell
# Run PSScriptAnalyzer on all scripts
pwsh -Command "Invoke-ScriptAnalyzer -Path './scripts' -Recurse"

# Exclude expected Write-Host warnings (acceptable for interactive scripts)
pwsh -Command "Invoke-ScriptAnalyzer -Path './scripts' -Recurse -ExcludeRule PSAvoidUsingWriteHost"
```

## Architecture

### Script Execution Flow

1. **Prerequisites** (`Install-Prerequisites.ps1`) - One-time server setup, downloads win-acme
2. **DNS Registration** (`Register-AcmeDns.ps1`) - One-time domain registration with acme-dns
3. **win-acme** - Handles certificate requests and renewals (external tool, scheduled daily)
4. **Post-Renewal Scripts** - Called BY win-acme after successful renewal to update service bindings

### Common.ps1 is the Foundation

All scripts dot-source `scripts/Helpers/Common.ps1` which provides:
- `Write-Log` - Unified logging to file, console, and Windows Event Log
- `Get-CertificateByThumbprint/Subject` - Certificate store operations
- `Test-CertificateValid` - Validates cert expiry, private key, etc.
- `Set/Get/Remove-WindowsCredential` - Secure credential storage via P/Invoke (not cmdkey)
- `Invoke-WithRetry` - Retry logic for network operations

### Credential Storage

Two methods available for acme-dns credentials:
- **JsonFile** (default): DPAPI-encrypted JSON in `%ProgramData%\WinCertManager\Config\acme-dns\`
- **CredentialManager**: Windows Credential Manager via P/Invoke API

The P/Invoke implementation in Common.ps1 (`WinCertManager.CredentialManager` class) avoids cmdkey.exe which exposes credentials on command line.

### Post-Renewal Scripts

`Update-RDGateway.ps1` and `Update-LDAPS.ps1` receive `{CertThumbprint}` from win-acme and:
1. Find the certificate in LocalMachine\My store
2. Validate it (expiry, private key, EKU)
3. Update service binding (RDS provider/WMI for RD Gateway, NTDS auto-detects for LDAPS)
4. Send events via `Send-CertificateEvent.ps1`

### Central Logging

`Send-CertificateEvent.ps1` sends to:
- Windows Event Log (always, source: WinCertManager)
- Webhook (HTTP POST, if configured)
- Syslog (UDP/TCP, if configured)

Config path validation prevents path traversal attacks.

## Key Patterns

- All scripts use `#Requires -Version 5.1` and optionally `#Requires -RunAsAdministrator`
- Destructive operations support `-WhatIf` via `[CmdletBinding(SupportsShouldProcess)]`
- Passwords are converted to SecureString immediately upon receipt from APIs
- PSScriptAnalyzer suppressions include justifications
- WMI usage in RD Gateway script is intentional (CIM doesn't support TSGatewayServer namespace methods)

## Security Notes

See `docs/security-review.md` for detailed security analysis. Key points:
- Authenticode signature verification on win-acme download
- P/Invoke for Credential Manager (avoids command-line exposure)
- Path traversal protection on config file loading
- DPAPI encryption for stored credentials

## Release Process

The release workflow (`.github/workflows/release.yml`):

1. **Branch protection** on main requires PR reviews and passing CI
2. **Tag push** (`v*`) triggers the release workflow
3. **Protected environment** requires manual approval before signing
4. **Authenticode signing** signs all `.ps1` files with timestamp
5. **GitHub Release** publishes signed ZIP with SHA256 checksum and public certificate

Signing secrets (`SIGNING_CERT_BASE64`, `SIGNING_CERT_PASSWORD`) are stored in the protected `release` environment.
