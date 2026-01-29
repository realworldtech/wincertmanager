# Windows Certificate Manager Toolkit

A toolkit for automating SSL certificate management on Windows Servers (2012+) using Let's Encrypt via win-acme.

## Supported Services

- **IIS** - Automatic HTTPS binding for websites
- **RD Gateway** - Remote Desktop Gateway SSL certificates
- **LDAPS** - Domain Controller LDAP over SSL

## Quick Start

### 1. Prepare the Server

```powershell
# Clone or copy toolkit to server
# Run prerequisites check and installation
.\scripts\Prerequisites\Install-Prerequisites.ps1
```

This will:
- Check Windows version and requirements
- Enable TLS 1.2 if needed
- Verify .NET Framework version
- Download and install win-acme
- Create renewal scheduled task

### 2. Configure DNS Validation

Choose one method:

**Option A: acme-dns (Recommended)**
```powershell
# Register domain
.\scripts\AcmeDns\Register-AcmeDns.ps1 -Domain "www.example.com"

# Add the CNAME record shown to your DNS
# _acme-challenge.www.example.com -> <subdomain>.acmedns.realworld.net.au
```

**Option B: CloudFlare**
1. Create API token at CloudFlare (Zone > DNS > Edit permission)
2. Use token during win-acme configuration

### 3. Request Certificate

Run win-acme and follow prompts:
```powershell
C:\Tools\win-acme\wacs.exe
```

For RD Gateway or LDAPS, use the post-renewal scripts:
```
--installation script
--script "C:\Tools\wincertmanager\scripts\PostRenewal\Update-RDGateway.ps1"
--scriptparameters "-Thumbprint {CertThumbprint} -RestartService"
```

## Project Structure

```
wincertmanager/
├── scripts/
│   ├── Prerequisites/          # Server preparation and win-acme installation
│   │   ├── Install-Prerequisites.ps1
│   │   └── Test-ServerReadiness.ps1
│   ├── AcmeDns/               # acme-dns registration and credential management
│   │   ├── Register-AcmeDns.ps1
│   │   └── Get-AcmeDnsCredential.ps1
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

### acme-dns

acme-dns delegates only the ACME challenge subdomain, providing:
- No full DNS provider access needed
- Works with any DNS provider supporting CNAME
- Simple one-time CNAME setup

RWTS acme-dns server: `https://acmedns.realworld.net.au`

### CloudFlare

Direct CloudFlare API integration:
- Requires CloudFlare-managed DNS
- Create API token with Zone > DNS > Edit permission
- Automatic record creation/cleanup

## Service-Specific Notes

### IIS

win-acme has native IIS support. No post-renewal script needed - win-acme handles binding updates automatically.

```powershell
wacs.exe --target iis --siteid 1 --validation acme-dns --installation iis
```

### RD Gateway

Requires post-renewal script to update SSL binding:

```powershell
wacs.exe --target manual --host gateway.example.com `
    --validation acme-dns `
    --installation script `
    --script "scripts\PostRenewal\Update-RDGateway.ps1" `
    --scriptparameters "-Thumbprint {CertThumbprint} -RestartService"
```

### LDAPS

Active Directory automatically detects certificates with Server Authentication EKU. The post-renewal script verifies configuration:

```powershell
wacs.exe --target manual --host dc01.example.com `
    --validation acme-dns `
    --installation script `
    --script "scripts\PostRenewal\Update-LDAPS.ps1" `
    --scriptparameters "-Thumbprint {CertThumbprint} -TestConnection"
```

**Note:** Internal-only domains (`.local`) cannot use Let's Encrypt. Use a public domain with split-brain DNS.

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

See [docs/troubleshooting.md](docs/troubleshooting.md) for common issues.

## Documentation

| Guide | Description |
|-------|-------------|
| [Customer Onboarding](docs/customer-onboarding.md) | Setup guide and decision tree |
| [IIS Setup](docs/iis-setup.md) | IIS certificate automation |
| [RD Gateway Setup](docs/rdgateway-setup.md) | Remote Desktop Gateway certificates |
| [LDAPS Setup](docs/ldaps-setup.md) | Domain Controller LDAPS certificates |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and solutions |

## Key Paths

| Component | Default Location |
|-----------|------------------|
| win-acme | `C:\Tools\win-acme` |
| win-acme Config | `%ProgramData%\win-acme` |
| WinCertManager Config | `%ProgramData%\WinCertManager\Config` |
| WinCertManager Logs | `%ProgramData%\WinCertManager\Logs` |

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

Proprietary - RWTS Internal Use

## References

- [win-acme Documentation](https://www.win-acme.com/)
- [Let's Encrypt](https://letsencrypt.org/)
- [acme-dns](https://github.com/joohoi/acme-dns)
