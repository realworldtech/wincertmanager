# Security Review: Windows Certificate Manager Toolkit

**Review Date:** 2026-01-29
**Reviewer:** Security Review (Automated)
**Version Reviewed:** 1.0.0

## Executive Summary

This is a legitimate Windows Certificate Manager toolkit for automating SSL/TLS certificate management using Let's Encrypt and win-acme. The codebase demonstrates good security practices overall but has several areas that warrant attention.

**Overall Assessment:** The code is well-structured with reasonable security controls. However, several issues ranging from low to high severity should be addressed before production deployment.

---

## High Severity Issues

### 1. Credential Exposure via Command Line

**Location:** `scripts/AcmeDns/Register-AcmeDns.ps1:171`

```powershell
cmdkey /generic:$targetName /user:$($response.username) /pass:$($response.password) | Out-Null
```

**Issue:** When using CredentialManager storage method, the password is passed directly on the command line. This exposes the credential in:
- Process listing (`Get-Process`, Task Manager)
- Command history
- Windows Event Log (Process Creation events - Event ID 4688)
- EDR/Security monitoring tools

**Recommendation:** Use the Credential Manager API via .NET instead of the cmdkey command, or use PowerShell's `New-StoredCredential` from the CredentialManager module.

**Status:** FIXED - Implemented P/Invoke wrapper for Windows Credential Manager API in Common.ps1 (Set-WindowsCredential, Get-WindowsCredential, Remove-WindowsCredential, Test-WindowsCredentialExists)

### 2. Plaintext Password in Memory

**Location:** `scripts/AcmeDns/Register-AcmeDns.ps1:123-132`

```powershell
$credentialData = [PSCustomObject]@{
    ...
    Password = $response.password  # Plaintext password stored in PSCustomObject
    ...
}
```

**Issue:** The raw password from the acme-dns API response is stored in a PSCustomObject in memory before encryption. While transient, this creates a window where the password exists unprotected in memory and could be captured via memory dumps.

**Recommendation:** Convert to SecureString immediately upon receipt and never store the plaintext version.

**Status:** FIXED - Password is now converted to SecureString immediately after API response. The $credentialData object no longer contains plaintext password.

---

## Medium Severity Issues

### 3. Unsigned Binary Download Without Verification

**Location:** `scripts/Prerequisites/Install-Prerequisites.ps1:251-252`

```powershell
Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
```

**Issue:** win-acme is downloaded from GitHub and executed without:
- Verifying digital signatures
- Checking file hash against known-good values
- Validating Authenticode signatures on the extracted binaries

An attacker who compromises the GitHub release or performs a MITM attack could inject malicious code.

**Recommendation:**
- Verify the SHA256 hash of the downloaded ZIP against the published hash
- After extraction, verify `wacs.exe` has a valid Authenticode signature from the expected publisher

**Status:** FIXED - Added Authenticode signature verification after extraction. Invalid signatures abort installation and remove potentially compromised files.

### 4. SSL/TLS Validation Disabled

**Location:** `scripts/PostRenewal/Update-LDAPS.ps1:230-231`

```powershell
$sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false,
    { param($_sender, $_certificate, $_chain, $_sslPolicyErrors) return $true })
```

**Issue:** Certificate validation is completely disabled when testing LDAPS connectivity. While this is intentional for testing (to work with self-signed certs), it means the test doesn't validate the certificate chain.

**Recommendation:** Add a parameter to optionally enable strict validation, and log a warning when validation is skipped.

**Status:** FIXED - Added -StrictSslValidation parameter. Default behavior logs a verbose message about relaxed validation.

### 5. Webhook API Key Stored in Plaintext

**Location:** `config/logging-config.example.json:8`

```json
"apiKey": "your-api-key-here",
```

**Issue:** The webhook API key is stored in plaintext in the configuration file. Anyone with read access to this file can retrieve the API key.

**Recommendation:**
- Document that the API key should be DPAPI-encrypted similar to acme-dns credentials
- Consider implementing encrypted configuration values with a helper function

**Status:** To be fixed

### 6. Broad Error Suppression

**Multiple locations** using `-ErrorAction SilentlyContinue`:

- `Common.ps1:86` - Log file writing
- `Common.ps1:104` - Event log writing
- `Send-CertificateEvent.ps1:176` - Event log writing

**Issue:** Silent error suppression can hide security-relevant failures. For example, if event logging fails due to permission issues, security events may go unlogged without any indication.

**Recommendation:** Consider implementing a fallback logging mechanism or at least maintaining an internal error count that can be reported.

**Status:** FIXED - Added $script:LoggingErrors collection and Get-LoggingErrors function to track and retrieve logging failures for diagnostics.

---

## Low Severity Issues

### 7. Path Traversal in ConfigPath Parameter

**Location:** `scripts/Logging/Send-CertificateEvent.ps1:66`

```powershell
[string]$ConfigPath
```

**Issue:** The `ConfigPath` parameter accepts arbitrary paths without validation. While this requires elevated privileges to exploit, a malicious configuration file could be loaded.

**Recommendation:** Validate that the config path is within expected directories.

**Status:** FIXED - Added path validation to ensure ConfigPath is within allowed directories (ProgramData\WinCertManager or the toolkit directory).

### 8. No Integrity Verification of Dot-Sourced Scripts

**Multiple locations** (all scripts dot-source Common.ps1):

```powershell
$commonPath = Join-Path $PSScriptRoot '..\Helpers\Common.ps1'
if (Test-Path $commonPath) {
    . $commonPath
}
```

**Issue:** Scripts dot-source `Common.ps1` based on relative path without verifying file integrity. If an attacker can modify Common.ps1, all scripts that source it would be compromised.

**Recommendation:** Consider implementing script signing and/or hash verification.

**Status:** Deferred - Future enhancement (script signing)

### 9. Hardcoded Default ACME-DNS Server

**Location:** `scripts/AcmeDns/Register-AcmeDns.ps1:44`

```powershell
[string]$AcmeDnsServer = 'https://acmedns.realworld.net.au',
```

**Issue:** Users should be explicitly aware they're trusting this third-party server with their DNS challenge credentials. While documented, the default could lead to implicit trust.

**Recommendation:** Add a first-run warning or require explicit acknowledgment when using the default server.

**Status:** To be evaluated

### 10. Verbose Password Retrieval Option

**Location:** `scripts/AcmeDns/Get-AcmeDnsCredential.ps1:37-38`

```powershell
[Parameter(ParameterSetName = 'Single')]
[switch]$AsPlainText,
```

**Issue:** While documented with warnings, this provides an easy mechanism to retrieve credentials in plaintext, which could be misused in automated scripts or by less security-aware administrators.

**Recommendation:** Add additional safeguards such as requiring interactive confirmation, or logging when plaintext retrieval is used.

**Status:** FIXED - Get-WindowsCredential now logs a warning when credentials are retrieved as plaintext.

---

## Positive Security Practices Observed

1. **DPAPI Encryption** - Credentials are encrypted using Windows DPAPI, providing machine/user-bound encryption
2. **TLS 1.2 Enforcement** - All network communications explicitly set TLS 1.2 minimum
3. **Administrator Requirements** - Scripts that require elevated privileges declare `#Requires -RunAsAdministrator`
4. **Parameter Validation** - Proper use of `ValidateSet`, `ValidateNotNullOrEmpty` attributes
5. **Certificate Validation** - Thorough certificate validation including EKU checks, expiry, private key presence
6. **Windows Event Logging** - Security-relevant events are logged to Windows Event Log
7. **Retry Logic** - Network operations include retry logic to handle transient failures
8. **WhatIf Support** - Destructive operations support `-WhatIf` for safe testing
9. **Credential Manager Option** - Alternative to file-based storage using Windows Credential Manager
10. **No Hardcoded Secrets** - No secrets hardcoded in the source code

---

## Recommendations Summary

| Priority | Issue | Effort | Status |
|----------|-------|--------|--------|
| High | Replace cmdkey with .NET Credential Manager API | Medium | FIXED |
| High | Convert password to SecureString immediately upon API response | Low | FIXED |
| Medium | Add hash/signature verification for win-acme download | Medium | FIXED |
| Medium | Add option for strict SSL validation in LDAPS test | Low | FIXED |
| Medium | Document/implement encrypted webhook API key storage | Low | To Fix |
| Medium | Add fallback mechanism for suppressed errors | Medium | FIXED |
| Low | Validate ConfigPath parameter | Low | FIXED |
| Low | Consider script signing | High | Deferred |
| Low | Add warning for default ACME-DNS server | Low | To Evaluate |
| Low | Log plaintext credential retrieval | Low | FIXED |

---

## Conclusion

The Windows Certificate Manager Toolkit demonstrates solid security practices for its intended purpose. The identified issues are addressable and do not indicate fundamental design flaws. The high-severity issues around credential handling should be prioritized before production deployment, particularly in environments with strict security requirements.

---

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-29 | 1.0 | Initial security review |
| 2026-01-29 | 1.1 | Fixed: Credential Manager API (P/Invoke), SecureString password handling, Authenticode verification, strict SSL validation option, logging error tracking, ConfigPath validation, plaintext retrieval logging |
