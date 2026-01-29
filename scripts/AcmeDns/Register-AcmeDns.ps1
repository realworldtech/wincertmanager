#Requires -Version 5.1
<#
.SYNOPSIS
    Registers a domain with an acme-dns server for DNS-01 validation.

.DESCRIPTION
    This script registers a new domain with an acme-dns server and stores
    the credentials securely. It outputs the required CNAME record that
    must be added to the domain's DNS.

.PARAMETER Domain
    The domain name to register (e.g., www.example.com).

.PARAMETER AcmeDnsServer
    The acme-dns server URL. Default: https://auth.acme-dns.io

.PARAMETER StorageMethod
    How to store the credentials: CredentialManager or JsonFile.
    Default: JsonFile (DPAPI encrypted)

.PARAMETER ApiKey
    API key for authenticated acme-dns servers. Required for RWTS acme-dns.
    Format: acmedns_xxxxx...

.PARAMETER ApiKeyId
    API key ID for authenticated acme-dns servers. Required for RWTS acme-dns.
    Format: key_xxxxx...

.PARAMETER Force
    Overwrite existing credentials if they exist.

.EXAMPLE
    .\Register-AcmeDns.ps1 -Domain 'www.example.com'

.EXAMPLE
    .\Register-AcmeDns.ps1 -Domain 'mail.example.com' -AcmeDnsServer 'https://auth.acme-dns.io'

.EXAMPLE
    .\Register-AcmeDns.ps1 -Domain 'dc01.internal.example.com' -ApiKey 'acmedns_xxx' -ApiKeyId 'key_xxx'

.NOTES
    Author: Real World Technology Solutions
    Version: 1.0.0
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'Required for DPAPI encryption of credentials received from acme-dns API')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [Parameter()]
    [string]$AcmeDnsServer = 'https://auth.acme-dns.io',

    [Parameter()]
    [ValidateSet('CredentialManager', 'JsonFile')]
    [string]$StorageMethod = 'JsonFile',

    [Parameter()]
    [string]$ApiKey,

    [Parameter()]
    [string]$ApiKeyId,

    [Parameter()]
    [switch]$Force
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

# Initialize
Initialize-WinCertManager
Write-Log "Registering domain '$Domain' with acme-dns server: $AcmeDnsServer" -Level Info

# Normalize domain
$Domain = $Domain.ToLower().Trim()

# Check for existing registration
$credentialFile = Get-SecureCredentialFile -Name $Domain

if ((Test-Path $credentialFile) -and -not $Force) {
    Write-Log "Credentials already exist for domain '$Domain'. Use -Force to overwrite." -Level Warning
    Write-Log "Credential file: $credentialFile" -Level Info

    # Load and display existing info
    try {
        $existingCreds = Get-AcmeDnsCredential -Domain $Domain
        Write-Host ''
        Write-Host 'Existing registration found:' -ForegroundColor Yellow
        Write-Host "  Subdomain: $($existingCreds.Subdomain)" -ForegroundColor Cyan
        Write-Host "  Full Name: $($existingCreds.FullDomain)" -ForegroundColor Cyan
        Write-Host ''
        Write-Host 'Required CNAME record:' -ForegroundColor Yellow
        Write-Host "  _acme-challenge.$Domain  CNAME  $($existingCreds.FullDomain)" -ForegroundColor Green
    }
    catch {
        Write-Log "Could not read existing credentials: $($_.Exception.Message)" -Level Warning
    }

    return
}

# Ensure TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Register with acme-dns server
$registerUrl = "$($AcmeDnsServer.TrimEnd('/'))/register"

Write-Log "Calling acme-dns register endpoint: $registerUrl" -Level Verbose

# Build headers for authenticated acme-dns servers
$headers = @{
    'Content-Type' = 'application/json'
}
if ($ApiKey) {
    $headers['X-Api-Key'] = $ApiKey
    Write-Log 'Using API key authentication' -Level Verbose
}
if ($ApiKeyId) {
    $headers['X-Api-User'] = $ApiKeyId
}

try {
    $response = Invoke-WithRetry -Description 'acme-dns registration' -ScriptBlock {
        $params = @{
            Uri             = $registerUrl
            Method          = 'Post'
            Headers         = $headers
            UseBasicParsing = $true
        }
        Invoke-RestMethod @params
    }
}
catch {
    Write-Log "Failed to register with acme-dns server: $($_.Exception.Message)" -Level Error
    throw
}

# Validate response
if (-not $response.subdomain -or -not $response.username -or -not $response.password) {
    Write-Log 'Invalid response from acme-dns server. Missing required fields.' -Level Error
    throw 'Invalid acme-dns registration response'
}

Write-Log 'Registration successful. Storing credentials...' -Level Info

# SECURITY: Convert password to SecureString immediately to minimize plaintext exposure
$securePassword = ConvertTo-SecureString -String $response.password -AsPlainText -Force

# Prepare credential metadata (no plaintext password stored in this object)
$credentialData = [PSCustomObject]@{
    Domain = $Domain
    AcmeDnsServer = $AcmeDnsServer
    Subdomain = $response.subdomain
    FullDomain = $response.fulldomain
    Username = $response.username
    AllowFrom = $response.allowfrom
    RegisteredAt = (Get-Date).ToString('o')
}

# Store credentials
switch ($StorageMethod) {
    'JsonFile' {
        # Use DPAPI encryption for the password
        $encryptedPassword = ConvertFrom-SecureString -SecureString $securePassword

        $storageData = [PSCustomObject]@{
            Domain = $credentialData.Domain
            AcmeDnsServer = $credentialData.AcmeDnsServer
            Subdomain = $credentialData.Subdomain
            FullDomain = $credentialData.FullDomain
            Username = $credentialData.Username
            EncryptedPassword = $encryptedPassword
            AllowFrom = $credentialData.AllowFrom
            RegisteredAt = $credentialData.RegisteredAt
            StorageMethod = 'DPAPI'
        }

        $storageData | ConvertTo-Json -Depth 5 | Set-Content -Path $credentialFile -Force
        Write-Log "Credentials stored at: $credentialFile" -Level Info
    }

    'CredentialManager' {
        # Store in Windows Credential Manager using secure API (not cmdkey)
        $targetName = "acme-dns:$Domain"

        # Remove existing credential if present
        $null = Remove-WindowsCredential -Target $targetName

        # Add new credential using secure P/Invoke API
        # This avoids exposing the password on the command line
        $stored = Set-WindowsCredential -Target $targetName -Username $response.username -SecurePassword $securePassword

        if (-not $stored) {
            Write-Log 'Failed to store credential in Windows Credential Manager' -Level Error
            throw 'Failed to store credential in Windows Credential Manager'
        }

        # Store additional metadata in JSON file (no sensitive data)
        $metadataFile = Get-SecureCredentialFile -Name "$Domain.meta"
        $metadata = [PSCustomObject]@{
            Domain = $credentialData.Domain
            AcmeDnsServer = $credentialData.AcmeDnsServer
            Subdomain = $credentialData.Subdomain
            FullDomain = $credentialData.FullDomain
            AllowFrom = $credentialData.AllowFrom
            RegisteredAt = $credentialData.RegisteredAt
            StorageMethod = 'CredentialManager'
            CredentialTarget = $targetName
        }
        $metadata | ConvertTo-Json -Depth 5 | Set-Content -Path $metadataFile -Force

        Write-Log "Credentials stored in Windows Credential Manager as: $targetName" -Level Info
    }
}

# Output results
Write-Host ''
Write-Host '========================================' -ForegroundColor Cyan
Write-Host '    ACME-DNS REGISTRATION COMPLETE' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''
Write-Host 'Registration Details:' -ForegroundColor Yellow
Write-Host "  Domain:     $Domain" -ForegroundColor White
Write-Host "  Subdomain:  $($credentialData.Subdomain)" -ForegroundColor White
Write-Host "  Full Name:  $($credentialData.FullDomain)" -ForegroundColor White
Write-Host "  Server:     $AcmeDnsServer" -ForegroundColor White
Write-Host ''
Write-Host '========================================' -ForegroundColor Green
Write-Host '  REQUIRED DNS CONFIGURATION' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor Green
Write-Host ''
Write-Host 'Add the following CNAME record to your DNS:' -ForegroundColor Yellow
Write-Host ''
Write-Host "  Name:   _acme-challenge.$Domain" -ForegroundColor Cyan
Write-Host "  Type:   CNAME" -ForegroundColor Cyan
Write-Host "  Value:  $($credentialData.FullDomain)" -ForegroundColor Cyan
Write-Host ''
Write-Host 'Example DNS record (BIND format):' -ForegroundColor Gray
Write-Host "  _acme-challenge.$Domain.  IN  CNAME  $($credentialData.FullDomain)." -ForegroundColor Gray
Write-Host ''
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''
Write-Host 'Next Steps:' -ForegroundColor Yellow
Write-Host '  1. Add the CNAME record to your DNS provider' -ForegroundColor White
Write-Host '  2. Wait for DNS propagation (typically 5-30 minutes)' -ForegroundColor White
Write-Host '  3. Verify with: nslookup -type=CNAME _acme-challenge.$Domain' -ForegroundColor White
Write-Host '  4. Configure win-acme to use acme-dns validation' -ForegroundColor White
Write-Host ''

# Log to central logging
try {
    $loggingScript = Join-Path $PSScriptRoot '..\Logging\Send-CertificateEvent.ps1'
    if (Test-Path $loggingScript) {
        & $loggingScript -EventType 'AcmeDnsRegistration' -Domain $Domain -Message "Registered with acme-dns server $AcmeDnsServer" -Status 'Success'
    }
}
catch {
    Write-Log "Could not send logging event: $($_.Exception.Message)" -Level Verbose
}

# Return credential data (without password for security)
[PSCustomObject]@{
    Domain = $credentialData.Domain
    AcmeDnsServer = $credentialData.AcmeDnsServer
    Subdomain = $credentialData.Subdomain
    FullDomain = $credentialData.FullDomain
    CnameRecord = "_acme-challenge.$Domain"
    CnameTarget = $credentialData.FullDomain
    RegisteredAt = $credentialData.RegisteredAt
}
