# RD Gateway Certificate Automation Setup

This guide covers setting up automated SSL certificates for Remote Desktop Gateway using win-acme.

## Prerequisites

- [ ] Windows Server with RD Gateway role installed
- [ ] win-acme installed (run `Install-Prerequisites.ps1`)
- [ ] DNS validation configured (acme-dns or CloudFlare)
- [ ] Domain pointing to the RD Gateway server

## Overview

RD Gateway certificate automation requires:
1. win-acme to obtain and renew certificates
2. Post-renewal script to update RD Gateway binding

Unlike IIS, RD Gateway doesn't have native win-acme integration, so we use a script-based installation.

## Setup Process

### Step 1: Verify RD Gateway Service

```powershell
# Check service is installed and running
Get-Service -Name TSGateway

# Check RD Gateway module
Get-Module -ListAvailable -Name RemoteDesktopServices
```

### Step 2: Verify DNS Configuration

Ensure DNS validation is configured:

```powershell
# For acme-dns, verify registration
.\scripts\AcmeDns\Get-AcmeDnsCredential.ps1 -Domain "gateway.example.com"
```

### Step 3: Configure win-acme

Run win-acme with script installation:

```powershell
cd C:\Tools\win-acme

.\wacs.exe --target manual --host gateway.example.com `
    --validation acme-dns `
    --validationmode dns-01 `
    --acmednsserver "https://acmedns.realworld.net.au" `
    --store certificatestore `
    --installation script `
    --script "C:\Tools\wincertmanager\scripts\PostRenewal\Update-RDGateway.ps1" `
    --scriptparameters "-Thumbprint {CertThumbprint} -RestartService"
```

Or for CloudFlare:

```powershell
.\wacs.exe --target manual --host gateway.example.com `
    --validation cloudflare `
    --validationmode dns-01 `
    --cloudflareapitoken "your-token-here" `
    --store certificatestore `
    --installation script `
    --script "C:\Tools\wincertmanager\scripts\PostRenewal\Update-RDGateway.ps1" `
    --scriptparameters "-Thumbprint {CertThumbprint} -RestartService"
```

### Interactive Setup

Alternatively, run `wacs.exe` interactively:

```
M: Create certificate (full options)

How would you like to select the domains?
2: Manual input

Enter host names: gateway.example.com

How would you like to validate?
[Select DNS-01]

[Select acme-dns or cloudflare]

[Enter credentials]

Which store do you want to use?
1: Windows Certificate Store

What installation step should run next?
4: Run a script

Path to script: C:\Tools\wincertmanager\scripts\PostRenewal\Update-RDGateway.ps1

Parameters: -Thumbprint {CertThumbprint} -RestartService
```

## Post-Renewal Script Details

The `Update-RDGateway.ps1` script:

1. Finds the renewed certificate by thumbprint
2. Validates certificate has private key and isn't expired
3. Updates RD Gateway SSL binding via:
   - RDS PowerShell provider (preferred)
   - WMI (fallback for older systems)
4. Optionally restarts the TSGateway service
5. Logs success/failure to Windows Event Log and central logging

### Script Parameters

| Parameter | Description |
|-----------|-------------|
| `-Thumbprint` | Certificate thumbprint (provided by win-acme as `{CertThumbprint}`) |
| `-Subject` | Alternative: find certificate by subject name |
| `-RestartService` | Restart TSGateway service after binding update |
| `-WhatIf` | Preview changes without applying |

### Manual Execution

To manually update the binding:

```powershell
.\scripts\PostRenewal\Update-RDGateway.ps1 -Subject "gateway.example.com" -RestartService
```

## Verification

### Check Current Certificate

Using RDS PowerShell provider:

```powershell
Import-Module RemoteDesktopServices
Get-Item RDS:\GatewayServer\SSLCertificate\Thumbprint | Select-Object CurrentValue
```

Using WMI:

```powershell
$gw = Get-WmiObject -Namespace root\TSGatewayServer -Class Win32_TSGatewayServerSettings
$gw.SSLCertificateSHA1Hash
```

### Test SSL Connection

```powershell
# Test TCP connectivity
Test-NetConnection gateway.example.com -Port 443

# Check certificate
$result = Invoke-WebRequest -Uri "https://gateway.example.com/rpc" -UseBasicParsing -ErrorAction SilentlyContinue
```

### Check Event Logs

```powershell
# win-acme events
Get-EventLog -LogName Application -Source "win-acme" -Newest 10

# WinCertManager events
Get-EventLog -LogName Application -Source "WinCertManager" -Newest 10

# RD Gateway events
Get-EventLog -LogName "Microsoft-Windows-TerminalServices-Gateway/Operational" -Newest 10
```

### Browser Test

1. Navigate to `https://gateway.example.com/RDWeb` (if RD Web Access is installed)
2. Check certificate details in browser
3. Verify issuer is Let's Encrypt

## RD Web Access

If RD Web Access is also installed, the same certificate can be used for both:

```powershell
# The certificate is shared with IIS for RD Web
# win-acme can also update IIS binding
.\wacs.exe --target manual --host gateway.example.com `
    --validation acme-dns `
    --acmednsserver "https://acmedns.realworld.net.au" `
    --store certificatestore `
    --installation iis,script `
    --installationsiteid 1 `
    --script "C:\Tools\wincertmanager\scripts\PostRenewal\Update-RDGateway.ps1" `
    --scriptparameters "-Thumbprint {CertThumbprint} -RestartService"
```

## High Availability Considerations

### Multiple RD Gateway Servers

Each server needs its own certificate (unless using load balancer with SSL termination):

1. Run setup on each server
2. Use the same domain name
3. Each server renews independently

### Load Balancer

If SSL terminates at the load balancer:
- Certificate only needed on load balancer
- Consider using load balancer's native certificate management

If SSL passthrough:
- Each gateway server needs the certificate
- Run win-acme on each server

## Troubleshooting

### Certificate Not Updating

1. Check win-acme logs: `%ProgramData%\win-acme\log`
2. Run script manually to see errors:
   ```powershell
   .\Update-RDGateway.ps1 -Subject "gateway.example.com" -Verbose
   ```

### "Access Denied" Errors

- Ensure script runs as SYSTEM (scheduled task default)
- Run manually as administrator to test

### RD Gateway Won't Start

If the service fails after certificate update:

```powershell
# Check the certificate is valid
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*gateway*" }
$cert | Select-Object Subject, NotAfter, HasPrivateKey

# Ensure private key is accessible
$cert.HasPrivateKey  # Should be True

# Check event logs
Get-EventLog -LogName System -Source "Service Control Manager" -Newest 20
```

### Binding Reverts

If the certificate binding keeps reverting:
- Check for Group Policy applying certificates
- Verify no other automation is competing
- Check scheduled tasks for conflicting scripts

## Example win-acme Answers

See [examples/win-acme-rdgateway.txt](../examples/win-acme-rdgateway.txt) for a complete interactive session example.

## Monitoring

Certificate events are logged to:
- Windows Event Log (Application log)
- Central logging (if configured)

Set up alerting on:
- Event ID 2001 (Failure) from source "WinCertManager"
- Event ID 1002 (Installation) for tracking updates
