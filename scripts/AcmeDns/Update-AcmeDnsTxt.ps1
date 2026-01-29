#Requires -Version 5.1
<#
.SYNOPSIS
    Updates acme-dns TXT records for win-acme DNS script validation.

.DESCRIPTION
    This script is called by win-acme during DNS-01 validation. It reads
    acme-dns credentials from WinCertManager's secure storage and updates
    the TXT record via the acme-dns API.

    Use this with win-acme's script validation plugin instead of the built-in
    acme-dns plugin for better unattended mode support.

.PARAMETER Action
    The action to perform: 'create' or 'delete'.
    Note: acme-dns doesn't require deletion as records are overwritten.

.PARAMETER Identifier
    The domain identifier being validated (e.g., www.example.com).

.PARAMETER RecordName
    The full TXT record name (e.g., _acme-challenge.www.example.com).

.PARAMETER Token
    The TXT record value to set.

.EXAMPLE
    # Called by win-acme:
    .\Update-AcmeDnsTxt.ps1 create example.com _acme-challenge.example.com "token123"

.EXAMPLE
    # Win-acme command line:
    wacs.exe --source manual --host example.com `
      --validation script `
      --dnscreatescript "C:\Tools\wincertmanager\scripts\AcmeDns\Update-AcmeDnsTxt.ps1" `
      --dnscreatescriptarguments "create {Identifier} {RecordName} {Token}" `
      --store certificatestore --certificatestore My

.NOTES
    Author: Real World Technology Solutions
    Version: 1.0.0

    This script serves as a template for acme-dns integration. Modify the
    AcmeDnsServer URL and credential retrieval as needed for your environment.
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'RecordName',
    Justification = 'RecordName is passed by win-acme but we use credentials file to get the acme-dns subdomain')]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('create', 'delete')]
    [string]$Action,

    [Parameter(Mandatory = $true, Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]$Identifier,

    [Parameter(Mandatory = $true, Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string]$RecordName,

    [Parameter(Mandatory = $true, Position = 3)]
    [ValidateNotNullOrEmpty()]
    [string]$Token
)

# Import common functions
$commonPath = Join-Path $PSScriptRoot '..\Helpers\Common.ps1'
if (Test-Path $commonPath) {
    . $commonPath
}
else {
    Write-Error "Common.ps1 not found at: $commonPath"
    exit 1
}

# Initialize logging
Initialize-WinCertManager

Write-Log "acme-dns update called: Action=$Action, Identifier=$Identifier, Token=$($Token.Substring(0, [Math]::Min(10, $Token.Length)))..." -Level Info

# Handle delete action (acme-dns doesn't require deletion)
if ($Action -eq 'delete') {
    Write-Log 'Delete action - no action required for acme-dns (records are overwritten)' -Level Info
    exit 0
}

# Normalize domain
$domain = $Identifier.ToLower().Trim()

# Retrieve acme-dns credentials from WinCertManager storage
Write-Log "Retrieving acme-dns credentials for domain: $domain" -Level Verbose

try {
    # Retrieve credentials via Get-AcmeDnsCredential.ps1
    $getCredScript = Join-Path $PSScriptRoot 'Get-AcmeDnsCredential.ps1'
    if (-not (Test-Path $getCredScript)) {
        throw "Get-AcmeDnsCredential.ps1 was not found in '$PSScriptRoot'. Cannot retrieve acme-dns credentials."
    }

    # Suppress verbose/warning output during credential retrieval
    $credential = & {
        $WarningPreference = 'SilentlyContinue'
        $VerbosePreference = 'SilentlyContinue'
        & $getCredScript -Domain $domain -AsPlainText
    }
}
catch {
    Write-Log "Failed to retrieve credentials for domain '$domain': $($_.Exception.Message)" -Level Error
    exit 1
}

if (-not $credential) {
    Write-Log "No credentials found for domain '$domain'. Run Register-AcmeDns.ps1 first." -Level Error
    exit 1
}

if (-not $credential.Password) {
    Write-Log "Password not available for domain '$domain'. Check credential storage." -Level Error
    exit 1
}

# Build acme-dns update URL
$acmeDnsServer = $credential.AcmeDnsServer
if (-not $acmeDnsServer) {
    # Default to public acme-dns server
    $acmeDnsServer = 'https://auth.acme-dns.io'
    Write-Log "No AcmeDnsServer in credentials, using default: $acmeDnsServer" -Level Warning
}

$updateUrl = "$($acmeDnsServer.TrimEnd('/'))/update"

# Prepare the update payload
$updateBody = @{
    subdomain = $credential.Subdomain
    txt       = $Token
} | ConvertTo-Json -Compress

Write-Log "Updating acme-dns TXT record at: $updateUrl" -Level Verbose
Write-Log "Subdomain: $($credential.Subdomain)" -Level Verbose

# Ensure TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Make the API call
try {
    $headers = @{
        'X-Api-User' = $credential.Username
        'X-Api-Key'  = $credential.Password
    }

    $response = Invoke-WithRetry -Description 'acme-dns TXT update' -MaxRetries 3 -DelaySeconds 2 -ScriptBlock {
        Invoke-RestMethod -Uri $updateUrl -Method Post -Body $updateBody -ContentType 'application/json' -Headers $headers -UseBasicParsing
    }

    # Verify response
    if ($response.txt -eq $Token) {
        Write-Log "Successfully updated TXT record to: $($response.txt)" -Level Info
        exit 0
    }
    else {
        Write-Log "TXT record update returned unexpected value: $($response.txt)" -Level Warning
        # Still consider this a success if we got a response
        exit 0
    }
}
catch {
    $errorMessage = $_.Exception.Message

    # Try to extract error from response body
    if ($_.Exception.Response) {
        try {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $responseBody = $reader.ReadToEnd()
            $reader.Close()

            $errorJson = $responseBody | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($errorJson.error) {
                $errorMessage = "acme-dns error: $($errorJson.error)"
            }
        }
        catch {
            # Ignore JSON parsing errors - we already have the original error message
            $null = $_
        }
    }

    Write-Log "Failed to update acme-dns TXT record: $errorMessage" -Level Error
    exit 1
}
