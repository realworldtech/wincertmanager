# Customer Onboarding Guide

This guide walks through the process of setting up automated SSL certificate management for a customer environment.

## Pre-Engagement Checklist

Before starting, gather the following information:

| Item | Description | Example |
|------|-------------|---------|
| Domain(s) | All domains requiring certificates | www.example.com, mail.example.com |
| Services | Which services need certificates | IIS, RD Gateway, LDAPS |
| DNS Provider | Customer's DNS management platform | CloudFlare, GoDaddy, internal DNS |
| Server OS | Windows Server version | Server 2019, Server 2016, Server 2012 R2 |
| Network | Firewall/proxy considerations | Outbound HTTPS access |
| Contacts | Technical contacts for DNS changes | IT admin email/phone |

## Decision Tree: Validation Method

```
                    ┌─────────────────────────────────┐
                    │   Does customer use CloudFlare? │
                    └─────────────────┬───────────────┘
                                      │
                    ┌─────────────────┴───────────────┐
                    │                                 │
                   YES                               NO
                    │                                 │
                    ▼                                 ▼
        ┌───────────────────┐           ┌───────────────────────┐
        │  Use CloudFlare   │           │ Can customer add      │
        │  DNS validation   │           │ CNAME records?        │
        └───────────────────┘           └───────────┬───────────┘
                                                    │
                                        ┌───────────┴───────────┐
                                        │                       │
                                       YES                     NO
                                        │                       │
                                        ▼                       ▼
                            ┌───────────────────┐   ┌───────────────────┐
                            │   Use acme-dns    │   │  HTTP-01 or       │
                            │   (Recommended)   │   │  manual process   │
                            └───────────────────┘   └───────────────────┘
```

## Method A: acme-dns Setup

**Best for:** Most customers, especially those with DNS providers that don't have API integration.

### Step 1: Register Domain with acme-dns

On the Windows server, run:

```powershell
# Navigate to scripts directory
cd C:\Tools\wincertmanager\scripts\AcmeDns

# Register the domain
.\Register-AcmeDns.ps1 -Domain "www.example.com"
```

The script outputs the required CNAME record, for example:
```
_acme-challenge.www.example.com  CNAME  a1b2c3d4.acmedns.realworld.net.au
```

### Step 2: Customer DNS Configuration

Send the following to the customer's IT team:

---

**Subject: DNS Record Required for SSL Certificate Automation**

Please add the following DNS record to enable automated SSL certificate management:

| Type | Name | Value |
|------|------|-------|
| CNAME | _acme-challenge.www.example.com | a1b2c3d4.acmedns.realworld.net.au |

This record delegates certificate validation to our acme-dns server. It does not affect normal website operation.

Please confirm once the record has been added.

---

### Step 3: Verify DNS Propagation

Wait 15-30 minutes, then verify:

```powershell
nslookup -type=CNAME _acme-challenge.www.example.com
```

Expected output should show the CNAME pointing to the acme-dns server.

### Step 4: Configure win-acme

Run win-acme and select:
1. M - Create certificate (full options)
2. Enter domain(s)
3. DNS-01 validation
4. acme-dns plugin
5. Server: https://acmedns.realworld.net.au

## Method B: CloudFlare Setup

**Best for:** Customers already using CloudFlare for DNS.

### Step 1: Create API Token

Guide the customer to create an API token:

1. CloudFlare Dashboard → My Profile → API Tokens
2. Create Token → Create Custom Token
3. Configure:
   - Name: win-acme-dns-validation
   - Permissions: Zone → DNS → Edit
   - Zone Resources: Include → Specific zone → [their zone]
4. Create and copy the token

See [CloudFlare Setup Guide](../config/cloudflare/README.md) for detailed instructions.

### Step 2: Configure win-acme

Run win-acme and select:
1. M - Create certificate (full options)
2. Enter domain(s)
3. DNS-01 validation
4. CloudFlare plugin
5. Enter the API token

## Server Preparation

### Step 1: Run Prerequisites Check

```powershell
# Check server readiness
.\scripts\Prerequisites\Test-ServerReadiness.ps1 -Detailed

# Install prerequisites and win-acme
.\scripts\Prerequisites\Install-Prerequisites.ps1
```

### Step 2: Address Any Issues

Common issues and fixes:

| Issue | Fix |
|-------|-----|
| TLS 1.2 not enabled | Script enables it automatically; reboot required |
| .NET < 4.7.2 | Download from Microsoft; may require reboot |
| PowerShell < 5.1 | Install WMF 5.1 from Microsoft |

### Step 3: Verify Outbound Connectivity

Ensure the server can reach:
- https://acme-v02.api.letsencrypt.org (Let's Encrypt API)
- https://acmedns.realworld.net.au (acme-dns server, if using)

```powershell
# Test connectivity
Invoke-WebRequest -Uri "https://acme-v02.api.letsencrypt.org/directory" -UseBasicParsing
```

## Service-Specific Setup

After completing DNS configuration, proceed to the appropriate guide:

| Service | Guide |
|---------|-------|
| IIS Websites | [IIS Setup Guide](iis-setup.md) |
| RD Gateway | [RD Gateway Setup Guide](rdgateway-setup.md) |
| LDAPS (Domain Controller) | [LDAPS Setup Guide](ldaps-setup.md) |

## Post-Setup Verification

### Scheduled Task

Verify the renewal task is configured:

```powershell
Get-ScheduledTask -TaskName "win-acme renew"
```

### Test Renewal

Run a test renewal to verify everything works:

```powershell
C:\Tools\win-acme\wacs.exe --renew --force
```

### Configure Monitoring (Optional)

Set up central logging:

1. Copy `config\logging-config.example.json` to `config\logging-config.json`
2. Configure webhook or syslog endpoint
3. Events will be sent on each renewal

## Handover Documentation

Provide the customer with:

1. **Certificate Summary**
   - Domain(s) covered
   - Expiry date (90 days from issue)
   - Auto-renewal schedule

2. **Important Paths**
   - win-acme: C:\Tools\win-acme
   - Logs: %ProgramData%\win-acme
   - Scripts: C:\Tools\wincertmanager

3. **Renewal Process**
   - Automatic daily check at 9:00 AM
   - Renews when < 30 days remaining
   - Logs to Windows Event Log

4. **Support Contact**
   - How to reach RWTS for issues
   - What to do if renewal fails

## Troubleshooting

See [Troubleshooting Guide](troubleshooting.md) for common issues and solutions.

## Timeline Checklist

| Day | Task | Owner |
|-----|------|-------|
| 1 | Gather requirements | RWTS |
| 1 | Register acme-dns / Send DNS instructions | RWTS |
| 1-3 | Add DNS record | Customer |
| 2-4 | Verify DNS, run prerequisites | RWTS |
| 2-4 | Configure win-acme, test certificate | RWTS |
| 2-4 | Verify service binding, test renewal | RWTS |
| 5 | Handover documentation | RWTS |
