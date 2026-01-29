# IIS Certificate Automation Setup

This guide covers setting up automated SSL certificates for IIS websites using win-acme.

## Prerequisites

- [ ] Windows Server with IIS installed
- [ ] win-acme installed (run `Install-Prerequisites.ps1`)
- [ ] DNS validation configured (acme-dns or CloudFlare)
- [ ] Domain pointing to the server

## IIS Automatic Binding

win-acme has built-in support for IIS and can automatically:
- Detect IIS sites and bindings
- Install certificates to the correct store
- Update HTTPS bindings
- Handle renewals

**Note:** Unlike RD Gateway and LDAPS, IIS certificates are handled directly by win-acme and don't require post-renewal scripts.

## Setup Process

### Step 1: Identify IIS Sites

List current IIS sites:

```powershell
Import-Module WebAdministration
Get-Website | Select-Object Name, ID, State, PhysicalPath
```

### Step 2: Check Existing Bindings

View current bindings:

```powershell
Get-WebBinding | Select-Object protocol, bindingInformation, sslFlags
```

### Step 3: Run win-acme

```powershell
cd C:\Tools\win-acme
.\wacs.exe
```

### Step 4: Interactive Configuration

Follow these selections:

```
 N: Create certificate (default settings)

 1: Single binding of an IIS site
 2: All bindings of an IIS site
 3: All bindings of multiple IIS sites

 [Select option based on your needs]

 [Select your site(s)]

 [Select DNS validation - acme-dns or cloudflare]

 [Enter credentials if prompted]
```

### For acme-dns:

```
How would you like to validate DNS?
[Select: acme-dns]

URL of the acme-dns API?
[Enter: https://acmedns.realworld.net.au]
```

The credentials stored by `Register-AcmeDns.ps1` will be used automatically.

### For CloudFlare:

```
How would you like to validate DNS?
[Select: cloudflare]

CloudFlare API Token?
[Enter your token]
```

## Advanced Options

### Multiple Domains (SAN Certificate)

To include multiple domains in one certificate:

```powershell
.\wacs.exe --target manual --host www.example.com,example.com,api.example.com `
    --validation cloudflare `
    --cloudflareapitoken "your-token" `
    --store certificatestore `
    --installation iis
```

### Specific IIS Site

```powershell
.\wacs.exe --target iis --siteid 1 `
    --validation cloudflare `
    --cloudflareapitoken "your-token" `
    --installation iis
```

### Wildcard Certificate

```powershell
.\wacs.exe --target manual --host "*.example.com" `
    --validation cloudflare `
    --cloudflareapitoken "your-token" `
    --store certificatestore `
    --installation iis
```

**Note:** Wildcard certificates require DNS validation.

## Verification

### Check Certificate Binding

```powershell
# View HTTPS bindings
Get-WebBinding -Protocol https | Format-List

# Get certificate details
$binding = Get-WebBinding -Protocol https -Name "Your Site Name"
$thumbprint = $binding.certificateHash
Get-ChildItem -Path Cert:\LocalMachine\My\$thumbprint | Select-Object Subject, NotAfter, Thumbprint
```

### Test HTTPS Connection

```powershell
# Test locally
Invoke-WebRequest -Uri "https://www.example.com" -UseBasicParsing

# Check certificate
$uri = "https://www.example.com"
$request = [System.Net.WebRequest]::Create($uri)
$request.GetResponse() | Out-Null
$cert = $request.ServicePoint.Certificate
Write-Host "Subject: $($cert.Subject)"
Write-Host "Expires: $($cert.GetExpirationDateString())"
```

### Browser Verification

1. Open the site in a browser
2. Click the padlock icon
3. Verify certificate details:
   - Issued to: your domain
   - Issued by: Let's Encrypt (or R3/R10/R11)
   - Valid dates

## Renewal Configuration

### View Current Renewals

```powershell
.\wacs.exe --list
```

### Test Renewal

```powershell
.\wacs.exe --renew --force
```

### Check Scheduled Task

```powershell
Get-ScheduledTask -TaskName "win-acme*" | Format-List TaskName, State, LastRunTime, NextRunTime
```

## Multiple Sites

### Option 1: Separate Certificates

Run win-acme for each site. Each gets its own certificate and renewal.

### Option 2: SAN Certificate

Include all domains in one certificate:

```powershell
.\wacs.exe --target manual --host site1.example.com,site2.example.com,site3.example.com `
    --validation cloudflare `
    --cloudflareapitoken "your-token" `
    --store certificatestore `
    --installation iis `
    --installationsiteid 1,2,3
```

### Option 3: Wildcard

Use `*.example.com` to cover all subdomains.

## SNI vs IP-Based Bindings

### SNI (Recommended)

Server Name Indication allows multiple HTTPS sites on one IP:

```powershell
# Check SNI is enabled
Get-WebBinding -Protocol https | Where-Object { $_.sslFlags -eq 1 }
```

win-acme creates SNI bindings by default on Server 2012 R2+.

### IP-Based (Legacy)

For older clients that don't support SNI, bind certificate to IP:

```powershell
# During win-acme setup, or manually:
New-WebBinding -Name "YourSite" -IPAddress "192.168.1.100" -Port 443 -Protocol https
```

## Centralized Certificate Store

For web farms, consider using:
- Central Certificate Store (CCS)
- win-acme CCS plugin

See win-acme documentation for CCS setup.

## Common Issues

### Binding Already Exists

If win-acme reports binding conflicts:

```powershell
# Remove old binding
Remove-WebBinding -Name "YourSite" -Protocol https -Port 443

# Run win-acme again
```

### Certificate Not Updating

Verify the scheduled task is running:

```powershell
# Check task status
Get-ScheduledTask -TaskName "win-acme renew" | Get-ScheduledTaskInfo

# Run manually
.\wacs.exe --renew --force --verbose
```

### Mixed Content Warnings

After enabling HTTPS, update your site to:
- Use relative URLs or `//` protocol-relative URLs
- Add `<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">`
- Update any hardcoded `http://` URLs

### HTTP to HTTPS Redirect

Add URL Rewrite rule:

```xml
<rule name="HTTP to HTTPS redirect" stopProcessing="true">
    <match url="(.*)" />
    <conditions>
        <add input="{HTTPS}" pattern="off" ignoreCase="true" />
    </conditions>
    <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
</rule>
```

Or via PowerShell:

```powershell
# Requires URL Rewrite module
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/YourSite' `
    -filter "system.webServer/rewrite/rules" `
    -name "." `
    -value @{name='HTTP to HTTPS redirect';stopProcessing='true'}
```

## Example win-acme Answers

See [examples/win-acme-iis.txt](../examples/win-acme-iis.txt) for a complete interactive session example.

## Monitoring

Certificate events are logged to:
- Windows Event Log (Application log, source: win-acme)
- win-acme log files: `%ProgramData%\win-acme\`

Configure central logging via `config\logging-config.json` for external monitoring.
