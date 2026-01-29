# Troubleshooting Guide

This guide covers common issues and solutions for the Windows Certificate Manager Toolkit.

## Quick Diagnostics

Run the readiness check to identify issues:

```powershell
.\scripts\Prerequisites\Test-ServerReadiness.ps1 -Detailed -Service All
```

## Prerequisites Issues

### TLS 1.2 Not Enabled

**Symptoms:**
- `Install-Prerequisites.ps1` reports TLS 1.2 not configured
- Cannot connect to Let's Encrypt API
- `Invoke-WebRequest` fails with protocol errors

**Solution:**
```powershell
# Run prerequisites script (enables TLS 1.2)
.\scripts\Prerequisites\Install-Prerequisites.ps1

# Reboot is required for registry changes to take effect
Restart-Computer
```

**Manual fix:**
```powershell
# Enable TLS 1.2 for .NET
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
```

### .NET Framework Version Too Low

**Symptoms:**
- win-acme won't start
- Missing assembly errors

**Solution:**
1. Download .NET Framework 4.8 from Microsoft
2. Install and reboot
3. Re-run `Test-ServerReadiness.ps1`

### PowerShell Version Too Low

**Symptoms:**
- Scripts fail with syntax errors
- Missing cmdlets

**Solution:**
1. Download WMF 5.1 from Microsoft
2. Install and reboot

## Network Issues

### Cannot Reach Let's Encrypt API

**Symptoms:**
```
Error connecting to https://acme-v02.api.letsencrypt.org
```

**Diagnosis:**
```powershell
# Test connectivity
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://acme-v02.api.letsencrypt.org/directory" -UseBasicParsing
```

**Solutions:**
1. Check firewall allows outbound HTTPS (port 443)
2. Check proxy settings:
   ```powershell
   netsh winhttp show proxy
   ```
3. Configure win-acme proxy if needed:
   ```
   %ProgramData%\win-acme\settings.json
   ```

### Cannot Reach acme-dns Server

**Symptoms:**
- `Register-AcmeDns.ps1` fails
- DNS validation times out

**Diagnosis:**
```powershell
Invoke-WebRequest -Uri "https://acmedns.realworld.net.au/health" -UseBasicParsing
```

**Solutions:**
1. Verify URL is correct
2. Check firewall/proxy
3. Try alternative acme-dns server or CloudFlare

## DNS Validation Issues

### Preliminary Validation Fails on Domain Controllers

**Symptoms:**
```
Preliminary validation failed on all nameservers
[syd03-ad01] Incorrect TXT record(s) found
```
The TXT record was created successfully on acme-dns, but win-acme reports validation failure.

**Cause:**
Win-acme uses the system's DNS servers for preliminary validation. On a Domain Controller, the system DNS is typically itself (127.0.0.1 or the DC's IP). The DC's DNS cannot resolve external acme-dns subdomains, so validation fails even though the record exists on public DNS.

**Diagnosis:**
```powershell
# Check what DNS servers win-acme is using
Get-Content "C:\Tools\win-acme\settings.json" | Select-String "DnsServers"

# Test resolution via system DNS vs public DNS
Resolve-DnsName _acme-challenge.yourserver.example.com -Type TXT
Resolve-DnsName _acme-challenge.yourserver.example.com -Type TXT -Server 8.8.8.8
```

**Solution:**
Configure win-acme to use public DNS servers for validation. Edit `C:\Tools\win-acme\settings.json`:

```json
{
  "Validation": {
    "DnsServers": [ "8.8.8.8", "1.1.1.1" ],
    ...
  }
}
```

Change `"DnsServers": [ "[System]" ]` to `"DnsServers": [ "8.8.8.8", "1.1.1.1" ]`.

This applies to any server using internal DNS that cannot resolve external zones.

### CNAME Record Not Found

**Symptoms:**
```
DNS validation failed: _acme-challenge.example.com not found
```

**Diagnosis:**
```powershell
nslookup -type=CNAME _acme-challenge.example.com
nslookup -type=CNAME _acme-challenge.example.com 8.8.8.8
```

**Solutions:**
1. Verify CNAME record is added correctly at DNS provider
2. Wait for propagation (up to 48 hours for some providers)
3. Check for typos in record name/value
4. Verify you're editing the correct DNS zone

### DNS Propagation Delay

**Symptoms:**
- nslookup works locally but validation fails
- Intermittent validation failures

**Solutions:**
1. Wait longer (some providers are slow)
2. Check DNS provider's propagation status
3. Test with multiple resolvers:
   ```powershell
   @('8.8.8.8', '1.1.1.1', '208.67.222.222') | ForEach-Object {
       Write-Host "Testing $_"
       nslookup -type=CNAME _acme-challenge.example.com $_
   }
   ```

### acme-dns Credential Issues

**Symptoms:**
```
Failed to decrypt password
Cannot authenticate to acme-dns
```

**Causes:**
- Credentials created by different user
- Credentials created on different machine
- Corrupted credential file

**Solutions:**
```powershell
# Re-register domain
.\scripts\AcmeDns\Register-AcmeDns.ps1 -Domain "example.com" -Force
```

### CloudFlare Token Issues

**Symptoms:**
```
CloudFlare API error: Authentication error
```

**Solutions:**
1. Verify token is correct (copy again from CloudFlare)
2. Check token hasn't expired
3. Verify token has DNS:Edit permission
4. Verify token has access to the specific zone

## Certificate Issues

### Certificate Not Found

**Symptoms:**
```
Certificate with thumbprint XXX not found
```

**Diagnosis:**
```powershell
# List all certificates
Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject, Thumbprint, NotAfter
```

**Solutions:**
1. Verify certificate was stored in correct store (LocalMachine\My)
2. Check win-acme logs for storage errors
3. Re-run win-acme to request new certificate

### Certificate Missing Private Key

**Symptoms:**
```
Certificate does not have a private key
Service won't start with certificate
```

**Diagnosis:**
```powershell
$cert = Get-ChildItem Cert:\LocalMachine\My\<thumbprint>
$cert.HasPrivateKey  # Should be True
```

**Solutions:**
1. Re-run win-acme (may need to delete old renewal)
2. Check certificate store permissions
3. Verify private key file exists:
   ```powershell
   $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
   ```

### Certificate Wrong EKU

**Symptoms:**
- LDAPS not working
- Services reject certificate

**Diagnosis:**
```powershell
$cert = Get-ChildItem Cert:\LocalMachine\My\<thumbprint>
$cert.EnhancedKeyUsageList
```

**Solution:**
Let's Encrypt certificates include Server Authentication EKU by default. If missing:
1. Delete the renewal in win-acme
2. Re-request certificate
3. Verify new certificate has correct EKU

## win-acme Issues

### win-acme Download Deleted by Install Script

**Symptoms:**
- `Install-Prerequisites.ps1` downloads win-acme but then deletes it
- Error about "Authenticode signature validation failed"

**Cause:**
Win-acme is signed by "WACS" with a self-signed certificate. If this certificate is not in the Windows trust store, the signature status returns `UnknownError` instead of `Valid`. Older versions of the toolkit treated this as a security failure.

**Solution:**
Update to the latest version of the toolkit (v1.0.2+), which correctly handles untrusted but cryptographically valid signatures. The script now only rejects downloads with `HashMismatch` (actual tampering).

If you must use an older version, manually download win-acme from https://www.win-acme.com/ and extract to `C:\Tools\win-acme\`.

### win-acme Won't Start

**Symptoms:**
- Crashes immediately
- Missing DLL errors

**Solutions:**
1. Install latest .NET Framework 4.8
2. Re-download win-acme (may be corrupted)
3. Check antivirus isn't blocking

### Scheduled Task Not Running

**Diagnosis:**
```powershell
Get-ScheduledTask -TaskName "win-acme renew" | Get-ScheduledTaskInfo
```

**Solutions:**
1. Check task is enabled
2. Verify SYSTEM account has needed permissions
3. Check task history for errors
4. Re-create task:
   ```powershell
   C:\Tools\win-acme\wacs.exe --setuptaskscheduler
   ```

### Renewal Failing

**Diagnosis:**
```powershell
# Check logs
Get-Content "$env:ProgramData\win-acme\log\log-*.txt" -Tail 100

# Test renewal
C:\Tools\win-acme\wacs.exe --renew --force --verbose
```

**Common causes:**
1. DNS validation no longer works (check CNAME)
2. Network connectivity issues
3. Let's Encrypt rate limits
4. Certificate store permissions

### Rate Limiting

**Symptoms:**
```
Error: too many certificates already issued
Error: too many failed authorizations
```

**Solutions:**
1. Wait (rate limits reset weekly for most limits)
2. Use staging environment for testing:
   ```
   --baseuri https://acme-staging-v02.api.letsencrypt.org/
   ```
3. Review [Let's Encrypt rate limits](https://letsencrypt.org/docs/rate-limits/)

## Service-Specific Issues

### IIS Certificate Not Updating

**Diagnosis:**
```powershell
Import-Module WebAdministration
Get-WebBinding -Protocol https | Format-List
```

**Solutions:**
1. Verify win-acme IIS installation plugin is configured
2. Check IIS site ID matches configuration
3. Manually update binding:
   ```powershell
   $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*example.com*" } | Sort-Object NotAfter -Descending | Select-Object -First 1
   $binding = Get-WebBinding -Protocol https -Name "YourSite"
   $binding.AddSslCertificate($cert.Thumbprint, "My")
   ```

### RD Gateway Update Fails

**Diagnosis:**
```powershell
# Check service
Get-Service TSGateway

# Check current binding
Import-Module RemoteDesktopServices
Get-Item RDS:\GatewayServer\SSLCertificate
```

**Solutions:**
1. Verify TSGateway service is running
2. Run script manually with verbose:
   ```powershell
   .\Update-RDGateway.ps1 -Subject "gateway.example.com" -Verbose
   ```
3. Try WMI method:
   ```powershell
   $gw = Get-WmiObject -Namespace root\TSGatewayServer -Class Win32_TSGatewayServerSettings
   $gw.SetSSLCertificate("<thumbprint>")
   ```

### LDAPS Not Working

**Diagnosis:**
```powershell
# Test port
Test-NetConnection localhost -Port 636

# Check NTDS service
Get-Service NTDS
```

**Solutions:**
1. Verify this is a Domain Controller
2. Check certificate has Server Authentication EKU
3. Verify certificate subject matches DC FQDN
4. Restart NTDS (causes brief AD interruption):
   ```powershell
   Restart-Service NTDS -Force
   ```
5. Check Directory Service event log

## Logging and Monitoring Issues

### Events Not Being Sent

**Diagnosis:**
```powershell
# Check config
Get-Content "$env:ProgramData\WinCertManager\Config\logging-config.json"

# Test webhook manually
$testEvent = @{EventType='Test';Domain='test.example.com';Status='Success'} | ConvertTo-Json
Invoke-RestMethod -Uri "https://your-webhook-url" -Method Post -Body $testEvent -ContentType "application/json"
```

**Solutions:**
1. Verify logging-config.json exists and is valid JSON
2. Check `enabled: true` in config
3. Test network connectivity to webhook/syslog endpoint
4. Check Windows Event Log for local events

## Getting Help

### Collecting Diagnostic Information

Run this to gather diagnostic info:

```powershell
# Create diagnostic report
$report = @{
    Date = Get-Date
    Computer = $env:COMPUTERNAME
    OS = (Get-CimInstance Win32_OperatingSystem).Caption
    PSVersion = $PSVersionTable.PSVersion.ToString()
    DotNet = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release
    WinAcmePath = Get-WinAcmePath
    Services = @{
        IIS = (Get-Service W3SVC -ErrorAction SilentlyContinue).Status
        TSGateway = (Get-Service TSGateway -ErrorAction SilentlyContinue).Status
        NTDS = (Get-Service NTDS -ErrorAction SilentlyContinue).Status
    }
    Certificates = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like "*Let's Encrypt*" } | Select-Object Subject, Thumbprint, NotAfter
}
$report | ConvertTo-Json -Depth 5
```

### Log Locations

| Log | Location |
|-----|----------|
| win-acme | `%ProgramData%\win-acme\log\` |
| WinCertManager | `%ProgramData%\WinCertManager\Logs\` |
| Windows Events | Event Viewer → Application → Sources: win-acme, WinCertManager |
| IIS | `%SystemDrive%\inetpub\logs\` |
| RD Gateway | Event Viewer → Applications and Services Logs → Microsoft → Windows → TerminalServices-Gateway |

### Support Resources

- win-acme Documentation: https://www.win-acme.com/
- Let's Encrypt Community: https://community.letsencrypt.org/
- RWTS Support: Contact via appropriate channels
