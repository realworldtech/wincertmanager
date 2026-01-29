# LDAPS Certificate Automation Setup

This guide covers setting up automated SSL certificates for LDAPS (LDAP over SSL) on Windows Domain Controllers.

## Prerequisites

- [ ] Windows Server Domain Controller
- [ ] win-acme installed (run `Install-Prerequisites.ps1`)
- [ ] DNS validation configured (acme-dns or CloudFlare)
- [ ] Domain Controller FQDN resolves correctly

## Overview

LDAPS enables encrypted LDAP connections on port 636. For a Domain Controller to support LDAPS:

1. A certificate must be in the LocalMachine\My store
2. The certificate must have Server Authentication EKU
3. The certificate subject must match the DC's FQDN
4. Active Directory automatically detects and uses the certificate

## Important Considerations

### Automatic Certificate Selection

Active Directory Domain Services (NTDS) automatically selects a certificate for LDAPS based on these criteria:

1. Certificate is in LocalMachine\My (Personal) store
2. Has Server Authentication EKU (OID 1.3.6.1.5.5.7.3.1)
3. Has a private key
4. Is not expired
5. Subject matches the DC's FQDN or has appropriate SAN

NTDS monitors the certificate store and picks up new certificates automatically, usually without needing a service restart.

### Certificate Selection Priority

If multiple valid certificates exist, NTDS typically uses:
1. The certificate with the longest validity period
2. The most recently issued certificate

To avoid conflicts, consider removing old certificates after renewal.

## Setup Process

### Step 1: Determine DC FQDN

```powershell
# Get the DC's FQDN
$computerSystem = Get-CimInstance Win32_ComputerSystem
$fqdn = "$($computerSystem.Name).$($computerSystem.Domain)"
Write-Host "DC FQDN: $fqdn"

# Example: dc01.contoso.local
```

### Step 2: Register Domain with acme-dns

**Important:** The domain used must be the DC's public FQDN or a name that Let's Encrypt can validate. Internal-only domains (like `.local`) cannot get Let's Encrypt certificates.

Options:
- Use a public subdomain: `dc01.example.com`
- Use split-brain DNS so internal clients resolve the DC via the public name

```powershell
.\scripts\AcmeDns\Register-AcmeDns.ps1 -Domain "dc01.example.com"
```

### Step 3: Configure win-acme

```powershell
cd C:\Tools\win-acme

.\wacs.exe --target manual --host dc01.example.com `
    --validation acme-dns `
    --validationmode dns-01 `
    --acmednsserver "https://acmedns.realworld.net.au" `
    --store certificatestore `
    --installation script `
    --script "C:\Tools\wincertmanager\scripts\PostRenewal\Update-LDAPS.ps1" `
    --scriptparameters "-Thumbprint {CertThumbprint} -TestConnection"
```

Or for CloudFlare:

```powershell
.\wacs.exe --target manual --host dc01.example.com `
    --validation cloudflare `
    --validationmode dns-01 `
    --cloudflareapitoken "your-token-here" `
    --store certificatestore `
    --installation script `
    --script "C:\Tools\wincertmanager\scripts\PostRenewal\Update-LDAPS.ps1" `
    --scriptparameters "-Thumbprint {CertThumbprint} -TestConnection"
```

### Interactive Setup

Run `wacs.exe` interactively:

```
M: Create certificate (full options)

How would you like to select the domains?
2: Manual input

Enter host names: dc01.example.com

How would you like to validate?
[Select DNS-01]

[Select acme-dns or cloudflare]

[Enter credentials]

Which store do you want to use?
1: Windows Certificate Store

What installation step should run next?
4: Run a script

Path to script: C:\Tools\wincertmanager\scripts\PostRenewal\Update-LDAPS.ps1

Parameters: -Thumbprint {CertThumbprint} -TestConnection
```

## Post-Renewal Script Details

The `Update-LDAPS.ps1` script:

1. Verifies this is a Domain Controller
2. Finds the renewed certificate by thumbprint
3. Validates certificate properties:
   - Has private key
   - Not expired
   - Has Server Authentication EKU
4. Optionally tests LDAPS connectivity
5. Logs results to Windows Event Log

### Script Parameters

| Parameter | Description |
|-----------|-------------|
| `-Thumbprint` | Certificate thumbprint (provided by win-acme) |
| `-Subject` | Alternative: find certificate by subject name |
| `-TestConnection` | Test LDAPS port 636 after verification |
| `-ForceRebind` | Force NTDS to refresh certificate binding |
| `-WhatIf` | Preview changes without applying |

### Manual Execution

```powershell
.\scripts\PostRenewal\Update-LDAPS.ps1 -Subject "dc01.example.com" -TestConnection -Verbose
```

## Verification

### Check Certificate in Store

```powershell
# Find LDAPS-capable certificates
Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.HasPrivateKey -and
    $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.1'
} | Select-Object Subject, Thumbprint, NotAfter
```

### Test LDAPS Connectivity

```powershell
# Test port 636
Test-NetConnection localhost -Port 636

# Full LDAPS test
$ldapPath = "LDAP://dc01.example.com:636"
try {
    $connection = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
    $connection.RefreshCache()
    Write-Host "LDAPS connection successful"
} catch {
    Write-Host "LDAPS connection failed: $_"
}
```

### Using ldp.exe

1. Open `ldp.exe` (built-in Windows tool)
2. Connection → Connect
3. Server: localhost (or DC FQDN)
4. Port: 636
5. Check "SSL"
6. Click OK
7. Should connect successfully

### Using OpenSSL (if available)

```bash
openssl s_client -connect dc01.example.com:636 -showcerts
```

### Check Which Certificate LDAPS is Using

```powershell
# Connect and get the certificate
$tcpClient = New-Object System.Net.Sockets.TcpClient('localhost', 636)
$sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream())
$sslStream.AuthenticateAsClient('localhost')
$cert = $sslStream.RemoteCertificate
Write-Host "LDAPS Certificate: $($cert.Subject)"
Write-Host "Thumbprint: $([System.BitConverter]::ToString($cert.GetCertHash()).Replace('-',''))"
$sslStream.Close()
$tcpClient.Close()
```

## Multiple Domain Controllers

Each DC needs its own certificate with its specific FQDN:

### Option 1: Individual Certificates (Recommended)

Run the setup on each DC with its specific hostname:
- dc01.example.com
- dc02.example.com
- dc03.example.com

Each DC manages its own certificate renewal.

### Option 2: SAN Certificate

Create a certificate with all DC names as SANs:

```powershell
.\wacs.exe --target manual --host dc01.example.com,dc02.example.com,dc03.example.com `
    ...
```

Then distribute to all DCs. More complex to manage.

## Internal-Only Domains (.local)

Let's Encrypt cannot issue certificates for:
- `.local` domains
- `.internal` domains
- Private IP addresses
- Non-publicly-resolvable names

### Solutions:

1. **Split-Brain DNS**
   - Register public domain: `dc01.example.com`
   - Internal DNS resolves to internal IP
   - External DNS doesn't need to resolve (just for ACME)

2. **Subdomain Delegation**
   - Delegate `ad.example.com` internally
   - DCs become `dc01.ad.example.com`
   - Get certificates for those names

3. **Internal CA (Alternative)**
   - Deploy internal PKI (AD CS)
   - Auto-enroll DC certificates
   - No public certificate needed
   - Clients trust internal CA

## Troubleshooting

### LDAPS Not Working After Certificate Install

1. **Check certificate properties:**
   ```powershell
   $cert = Get-ChildItem Cert:\LocalMachine\My\<thumbprint>
   $cert | Format-List Subject, HasPrivateKey, NotAfter
   $cert.EnhancedKeyUsageList
   ```

2. **Verify private key permissions:**
   ```powershell
   # NTDS runs as SYSTEM - check SYSTEM has access
   $cert = Get-ChildItem Cert:\LocalMachine\My\<thumbprint>
   $keyPath = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
   ```

3. **Force certificate refresh:**
   ```powershell
   # Restart the NTDS service (causes brief AD interruption!)
   Restart-Service NTDS -Force
   ```

4. **Check event logs:**
   ```powershell
   Get-EventLog -LogName "Directory Service" -Newest 20
   ```

### Certificate Not Being Selected

If LDAPS uses wrong certificate:

1. Remove old/conflicting certificates from LocalMachine\My
2. Ensure new certificate has Server Authentication EKU
3. Verify subject/SAN matches DC FQDN
4. Restart NTDS service if needed

### "The server is not operational"

- Certificate may not have Server Authentication EKU
- Private key not accessible
- Certificate expired or not yet valid
- Subject doesn't match server name

## Security Considerations

1. **DNS Validation Only**
   - HTTP-01 validation won't work for DCs (port 80 typically not exposed)
   - DNS-01 is the secure choice for internal servers

2. **Certificate Security**
   - Let's Encrypt certificates are public
   - Internal clients should validate the certificate chain
   - Consider internal PKI for pure internal environments

3. **Renewal Monitoring**
   - Monitor for renewal failures
   - LDAPS stops working when certificate expires
   - Set up alerting via central logging

## Example win-acme Answers

See [examples/win-acme-ldaps.txt](../examples/win-acme-ldaps.txt) for a complete interactive session example.
