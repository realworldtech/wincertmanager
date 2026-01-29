# CloudFlare DNS Validation Setup

This guide explains how to configure CloudFlare API tokens for DNS-01 validation with win-acme.

## Overview

CloudFlare DNS validation allows win-acme to automatically create and clean up DNS TXT records for ACME challenges. This requires an API token with specific permissions.

## Creating a CloudFlare API Token

### Step 1: Access API Tokens

1. Log in to the [CloudFlare Dashboard](https://dash.cloudflare.com)
2. Click your profile icon (top right)
3. Select **My Profile**
4. Click **API Tokens** in the left sidebar
5. Click **Create Token**

### Step 2: Create Custom Token

Select **Create Custom Token** (not a template).

Configure the token with these settings:

| Setting | Value |
|---------|-------|
| **Token name** | `win-acme-dns-validation` (or similar descriptive name) |
| **Permissions** | Zone > DNS > Edit |
| **Zone Resources** | Include > Specific zone > *your-domain.com* |
| **Client IP Filtering** | (Optional) Limit to your server's IP |
| **TTL** | (Optional) Set expiration date |

### Step 3: Minimal Permissions

For the most restrictive setup, configure:

**Permissions:**
- Zone → DNS → Edit

**Zone Resources:**
- Include → Specific zone → [Select your zone]

This grants only DNS edit access to the specific zone(s) needed.

### Step 4: Copy the Token

After creating the token:
1. **Copy the token immediately** - it won't be shown again
2. Store it securely (password manager, secure notes)
3. The token starts with a long alphanumeric string

## Configuring win-acme

### Interactive Setup

When running win-acme:

```
1. Select: M - Create certificate (full options)
2. Select: 2 - Manual input
3. Enter your domain(s)
4. Select: [dns-01] DNS validation
5. Select: [cloudflare] CloudFlare
6. Enter your API token when prompted
```

### Command Line

```powershell
wacs.exe --target manual --host www.example.com `
    --validation cloudflare `
    --cloudflareapitoken "your-api-token-here" `
    --store certificatestore `
    --installation iis
```

## Security Best Practices

### 1. Use Zone-Specific Tokens

Never use a Global API Key. Always create tokens with:
- Specific zone access (not "All zones")
- Minimal permissions (DNS Edit only)

### 2. IP Restrictions

If your server has a static IP, add IP filtering:
- Client IP Address Filtering → Is in → [Your Server IP]

### 3. Token Rotation

Consider setting token expiration and rotating periodically:
- TTL → Custom → [Choose expiration date]

### 4. Audit Access

Regularly review:
- CloudFlare Dashboard → Audit Log
- Check for unexpected API activity

## Multiple Domains

### Same CloudFlare Account

If all domains are in the same CloudFlare account, you can:
1. Create one token with access to multiple zones
2. Or create separate tokens per zone (more secure)

### Different CloudFlare Accounts

You'll need separate tokens for each account. Configure win-acme with the appropriate token for each domain.

## Troubleshooting

### "Authentication error"

- Verify the token is copied correctly (no extra spaces)
- Check token hasn't expired
- Ensure token has DNS Edit permission

### "Zone not found"

- Verify the zone is active in CloudFlare
- Check token has access to the specific zone
- Domain must be using CloudFlare nameservers

### "Permission denied"

- Token needs Zone > DNS > Edit permission
- Not Zone > Zone Settings (different permission)
- Check zone-specific access is granted

### Rate Limiting

CloudFlare has API rate limits:
- 1200 requests per 5 minutes per user
- win-acme shouldn't hit these under normal use
- If rate limited, wait 5 minutes and retry

## Revoking Access

If a token is compromised:

1. Go to CloudFlare Dashboard → My Profile → API Tokens
2. Find the token
3. Click the three dots → Delete
4. Create a new token
5. Update win-acme configuration

## Alternative: API Key (Not Recommended)

CloudFlare also offers Global API Keys, but these:
- Have full account access
- Cannot be scoped to specific zones
- Are less secure

**Always use API Tokens instead of Global API Keys.**

## win-acme Configuration Files

win-acme stores CloudFlare configuration in:
```
%ProgramData%\win-acme\acme-v02.api.letsencrypt.org\
```

The API token is encrypted using DPAPI in the configuration file.

## References

- [CloudFlare API Tokens](https://developers.cloudflare.com/api/tokens/)
- [win-acme CloudFlare Plugin](https://www.win-acme.com/reference/plugins/validation/dns/cloudflare)
- [CloudFlare API Documentation](https://api.cloudflare.com/)
