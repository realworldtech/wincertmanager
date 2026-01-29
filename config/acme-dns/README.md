# acme-dns Configuration

This directory contains instructions for setting up acme-dns for DNS-01 validation with win-acme.

## What is acme-dns?

acme-dns is a limited DNS server designed specifically for handling ACME DNS-01 challenges. Instead of granting win-acme access to your primary DNS provider, you delegate only the `_acme-challenge` subdomain to acme-dns.

## Benefits

- **Security**: No need to give win-acme full access to your DNS provider
- **Simplicity**: Works with any DNS provider that supports CNAME records
- **Reliability**: Purpose-built for ACME challenges
- **Centralized**: One acme-dns server can handle multiple domains

## RWTS acme-dns Server

Real World Technology Solutions operates an acme-dns server at:

```
https://acmedns.realworld.net.au
```

## Setup Process

### 1. Register Your Domain

Use the provided PowerShell script to register your domain:

```powershell
.\scripts\AcmeDns\Register-AcmeDns.ps1 -Domain "www.example.com"
```

This will:
- Register the domain with the acme-dns server
- Store credentials securely (DPAPI encrypted)
- Output the required CNAME record

### 2. Add CNAME Record

Add the CNAME record to your DNS provider. The script will output something like:

```
_acme-challenge.www.example.com  CNAME  a1b2c3d4-e5f6-7890-abcd-ef1234567890.acmedns.realworld.net.au
```

### 3. Verify DNS Propagation

Wait for DNS propagation (typically 5-30 minutes), then verify:

```powershell
nslookup -type=CNAME _acme-challenge.www.example.com
```

### 4. Configure win-acme

When running win-acme, select:
- **Validation**: DNS-01 validation
- **Plugin**: acme-dns
- **Server**: https://acmedns.realworld.net.au

## Credential Storage

Credentials are stored in:
```
%ProgramData%\WinCertManager\Config\acme-dns\
```

Each domain has a JSON file containing:
- Subdomain assigned by acme-dns
- Username/password (DPAPI encrypted)
- Registration timestamp

### Retrieving Credentials

```powershell
# View credentials for a specific domain
.\scripts\AcmeDns\Get-AcmeDnsCredential.ps1 -Domain "www.example.com"

# List all registered domains
.\scripts\AcmeDns\Get-AcmeDnsCredential.ps1 -ListAll
```

## Security Considerations

1. **DPAPI Encryption**: Passwords are encrypted using Windows DPAPI, which is tied to the user/machine
2. **Credential Isolation**: Each domain has separate credentials
3. **Limited Scope**: acme-dns credentials only allow updating the specific TXT record, not your entire DNS
4. **Backup**: Consider backing up the credential files (they're machine-specific though)

## Troubleshooting

### Registration Failed

- Verify network connectivity to the acme-dns server
- Ensure TLS 1.2 is enabled (run `Install-Prerequisites.ps1`)
- Check firewall allows outbound HTTPS

### DNS Propagation Issues

- Wait longer (some DNS providers are slow)
- Check the CNAME is correctly formatted
- Verify with multiple DNS resolvers:
  ```
  nslookup -type=CNAME _acme-challenge.example.com 8.8.8.8
  nslookup -type=CNAME _acme-challenge.example.com 1.1.1.1
  ```

### Credential Decryption Failed

This usually means:
- Trying to use credentials stored by a different user
- Credentials were created on a different machine
- Re-register the domain with `Register-AcmeDns.ps1 -Force`

## Self-Hosted acme-dns

If you prefer to run your own acme-dns server:

1. Deploy acme-dns: https://github.com/joohoi/acme-dns
2. Configure DNS delegation for your acme-dns server
3. Use the `-AcmeDnsServer` parameter when registering:
   ```powershell
   .\Register-AcmeDns.ps1 -Domain "www.example.com" -AcmeDnsServer "https://acme-dns.yourdomain.com"
   ```

## References

- [acme-dns GitHub](https://github.com/joohoi/acme-dns)
- [win-acme acme-dns Documentation](https://www.win-acme.com/reference/plugins/validation/dns/acme-dns)
- [Let's Encrypt DNS-01 Challenge](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge)
