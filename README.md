# Windows Certificate Manager Toolkit

A toolkit for automating SSL certificate management on Windows Servers (2012+) using Let's Encrypt via win-acme.

## Supported Services

- **IIS** - Automatic HTTPS binding for websites
- **RD Gateway** - Remote Desktop Gateway SSL certificates
- **LDAPS** - Domain Controller LDAP over SSL

## Quick Start

### 0. Download the Toolkit

Download the latest signed release from [GitHub Releases](https://github.com/realworldtech/wincertmanager/releases):

1. Download `wincertmanager-x.x.x.zip` and `wincertmanager-x.x.x.zip.sha256`
2. Verify the SHA256 checksum
3. Extract to `C:\Tools\wincertmanager` (or your preferred location)
4. Import the signing certificate to trusted root (optional, for signature validation):
   ```powershell
   Import-Certificate -FilePath C:\Tools\wincertmanager\certs\rwts-codesign.cer -CertStoreLocation Cert:\LocalMachine\Root
   ```

### 1. Prepare the Server

```powershell
# Run prerequisites check and installation
.\scripts\Prerequisites\Install-Prerequisites.ps1
```

This will:
- Check Windows version and requirements
- Enable TLS 1.2 if needed
- Verify .NET Framework version
- Download and install win-acme to `C:\Tools\win-acme`
- Create renewal scheduled task

**Custom install path:**
```powershell
.\scripts\Prerequisites\Install-Prerequisites.ps1 -InstallPath "$env:ProgramFiles\win-acme"
```

### 2. Configure DNS Validation (acme-dns)

```powershell
# Register domain with acme-dns
.\scripts\AcmeDns\Register-AcmeDns.ps1 -Domain "server.example.com"

# Add the CNAME record shown in the output to your DNS provider
# _acme-challenge.server.example.com -> <subdomain>.acmedns.realworld.net.au
```

### 3. Request Certificate

Example for LDAPS on a Domain Controller:

```powershell
C:\Tools\win-acme\wacs.exe `
    --source manual --host dc01.example.com `
    --validation script `
    --dnscreatescript "C:\Tools\wincertmanager\scripts\AcmeDns\Update-AcmeDnsTxt.ps1" `
    --dnscreatescriptarguments "create {Identifier} {RecordName} {Token}" `
    --store certificatestore --certificatestore My `
    --installation script `
    --script "C:\Tools\wincertmanager\scripts\PostRenewal\Update-LDAPS.ps1" `
    --scriptparameters "-Thumbprint {CertThumbprint} -TestConnection" `
    --accepttos --emailaddress admin@example.com
```

See [Service-Specific Notes](#service-specific-notes) for IIS and RD Gateway examples.

## Project Structure

```
wincertmanager/
├── scripts/
│   ├── Prerequisites/          # Server preparation and win-acme installation
│   │   ├── Install-Prerequisites.ps1
│   │   └── Test-ServerReadiness.ps1
│   ├── AcmeDns/               # acme-dns registration and credential management
│   │   ├── Register-AcmeDns.ps1
│   │   ├── Get-AcmeDnsCredential.ps1
│   │   └── Update-AcmeDnsTxt.ps1   # DNS validation script for win-acme
│   ├── PostRenewal/           # Service-specific certificate binding scripts
│   │   ├── Update-RDGateway.ps1
│   │   └── Update-LDAPS.ps1
│   ├── Logging/               # Central logging functionality
│   │   └── Send-CertificateEvent.ps1
│   └── Helpers/               # Shared functions
│       └── Common.ps1
├── config/                    # Configuration templates
│   ├── logging-config.example.json
│   ├── acme-dns/
│   └── cloudflare/
├── docs/                      # Setup guides
│   ├── customer-onboarding.md
│   ├── iis-setup.md
│   ├── rdgateway-setup.md
│   ├── ldaps-setup.md
│   └── troubleshooting.md
└── examples/                  # win-acme configuration examples
    ├── win-acme-iis.txt
    ├── win-acme-rdgateway.txt
    └── win-acme-ldaps.txt
```

## Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Windows Server | 2012 | 2016+ |
| .NET Framework | 4.6.2 | 4.7.2+ |
| PowerShell | 5.0 | 5.1 |

## DNS Validation Methods

### acme-dns (Recommended)

acme-dns delegates only the ACME challenge subdomain, providing:
- No full DNS provider access needed
- Works with any DNS provider supporting CNAME
- Simple one-time CNAME setup
- Works reliably on Domain Controllers and internal servers

RWTS acme-dns server: `https://acmedns.realworld.net.au`

#### Setup Steps

1. **Register with acme-dns:**
   ```powershell
   .\scripts\AcmeDns\Register-AcmeDns.ps1 -Domain "server.example.com"
   ```

2. **Add the CNAME record** shown in the output to your DNS:
   ```
   _acme-challenge.server.example.com. CNAME <subdomain>.acmedns.realworld.net.au.
   ```

3. **Request certificate** using the script validation method (see examples below)

#### Script-Based Validation

This toolkit uses **script-based DNS validation** with win-acme rather than win-acme's built-in acme-dns plugin. This approach:
- Works reliably in unattended/automated scenarios
- Uses WinCertManager's secure DPAPI-encrypted credential storage
- Avoids issues with win-acme's preliminary DNS validation on Domain Controllers

The `Update-AcmeDnsTxt.ps1` script is configured for the RWTS acme-dns server by default. For other acme-dns servers, modify the script or credential storage as needed.

### CloudFlare

Direct CloudFlare API integration:
- Requires CloudFlare-managed DNS
- Create API token with Zone > DNS > Edit permission
- Automatic record creation/cleanup

## Service-Specific Notes

### IIS

win-acme has native IIS support. No post-renewal script needed - win-acme handles binding updates automatically.

```powershell
wacs.exe --source iis --siteid 1 `
    --validation script `
    --dnscreatescript "C:\Tools\wincertmanager\scripts\AcmeDns\Update-AcmeDnsTxt.ps1" `
    --dnscreatescriptarguments "create {Identifier} {RecordName} {Token}" `
    --installation iis
```

### RD Gateway

Requires post-renewal script to update SSL binding:

```powershell
wacs.exe --source manual --host gateway.example.com `
    --validation script `
    --dnscreatescript "C:\Tools\wincertmanager\scripts\AcmeDns\Update-AcmeDnsTxt.ps1" `
    --dnscreatescriptarguments "create {Identifier} {RecordName} {Token}" `
    --store certificatestore --certificatestore My `
    --installation script `
    --script "C:\Tools\wincertmanager\scripts\PostRenewal\Update-RDGateway.ps1" `
    --scriptparameters "-Thumbprint {CertThumbprint} -RestartService"
```

### LDAPS

Active Directory automatically detects certificates with Server Authentication EKU. The post-renewal script verifies configuration:

```powershell
wacs.exe --source manual --host dc01.example.com `
    --validation script `
    --dnscreatescript "C:\Tools\wincertmanager\scripts\AcmeDns\Update-AcmeDnsTxt.ps1" `
    --dnscreatescriptarguments "create {Identifier} {RecordName} {Token}" `
    --store certificatestore --certificatestore My `
    --installation script `
    --script "C:\Tools\wincertmanager\scripts\PostRenewal\Update-LDAPS.ps1" `
    --scriptparameters "-Thumbprint {CertThumbprint} -TestConnection"
```

**Note:** Internal-only domains (`.local`) cannot use Let's Encrypt. Use a publicly resolvable domain (e.g., `dc01.internal.example.com` where `example.com` is a real domain you control).

## Monitoring

### Windows Event Log

All certificate events are logged to Windows Event Log:
- Source: `WinCertManager`
- Log: Application

### Central Logging (Optional)

Configure `config/logging-config.json` for:
- Webhook notifications (HTTP POST)
- Syslog forwarding (UDP/TCP)

## Troubleshooting

Run the readiness check:
```powershell
.\scripts\Prerequisites\Test-ServerReadiness.ps1 -Detailed
```

### Domain Controllers and Internal DNS

When running on a Domain Controller or server using internal DNS, win-acme's preliminary DNS validation may fail because the internal DNS cannot resolve external acme-dns subdomains.

**Symptom:** Win-acme shows "Preliminary validation failed" even though the TXT record was created successfully.

**Solution:** Configure win-acme to use public DNS servers for validation. Edit `C:\Tools\win-acme\settings.json`:

```json
"Validation": {
    "DnsServers": [ "8.8.8.8", "1.1.1.1" ],
    ...
}
```

This tells win-acme to use Google/Cloudflare DNS for checking TXT records instead of the system's DNS.

See [docs/troubleshooting.md](docs/troubleshooting.md) for more common issues.

## Documentation

| Guide | Description |
|-------|-------------|
| [Customer Onboarding](docs/customer-onboarding.md) | Setup guide and decision tree |
| [IIS Setup](docs/iis-setup.md) | IIS certificate automation |
| [RD Gateway Setup](docs/rdgateway-setup.md) | Remote Desktop Gateway certificates |
| [LDAPS Setup](docs/ldaps-setup.md) | Domain Controller LDAPS certificates |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and solutions |

## Key Paths

| Component | Default Location | Configurable |
|-----------|------------------|--------------|
| win-acme | `C:\Tools\win-acme` | Yes (`-InstallPath`) |
| win-acme Config | `%ProgramData%\win-acme` | Via win-acme settings |
| WinCertManager Toolkit | `C:\Tools\wincertmanager` | Manual (copy anywhere) |
| WinCertManager Config | `%ProgramData%\WinCertManager\Config` | No |
| WinCertManager Logs | `%ProgramData%\WinCertManager\Logs` | No |

## Certificate Renewal

Certificates are renewed automatically:
- Scheduled task runs daily at 9:00 AM
- Renewal triggered when < 30 days remain
- Let's Encrypt certificates valid for 90 days

Check scheduled task status:
```powershell
Get-ScheduledTask -TaskName "win-acme renew" | Get-ScheduledTaskInfo
```

## Security Considerations

1. **DNS Validation**: Preferred over HTTP-01 for internal servers
2. **Credential Storage**: DPAPI encryption for acme-dns credentials
3. **API Tokens**: Use minimal permissions (zone-specific, DNS Edit only)
4. **Private Keys**: Stored in Windows certificate store with appropriate ACLs

## Contributing

This toolkit is maintained by Real World Technology Solutions.

## License

This project is licensed under [CC BY-NC 4.0](LICENSE) (Creative Commons Attribution-NonCommercial 4.0).

- **Free for non-commercial use** with attribution
- **Commercial use** requires permission from [Real World Technology Solutions](https://rwts.com.au)

## References

- [win-acme Documentation](https://www.win-acme.com/)
- [Let's Encrypt](https://letsencrypt.org/)
- [acme-dns](https://github.com/joohoi/acme-dns)
