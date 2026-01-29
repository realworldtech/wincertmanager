#Requires -Version 5.1
<#
.SYNOPSIS
    Retrieves stored acme-dns credentials for a domain.

.DESCRIPTION
    This script retrieves acme-dns credentials that were stored by
    Register-AcmeDns.ps1. Credentials are decrypted from DPAPI-protected
    storage or retrieved from Windows Credential Manager.

.PARAMETER Domain
    The domain name to retrieve credentials for.

.PARAMETER AsPlainText
    If specified, returns the password as plain text. Use with caution.

.PARAMETER ListAll
    List all registered domains without showing sensitive data.

.EXAMPLE
    .\Get-AcmeDnsCredential.ps1 -Domain 'www.example.com'

.EXAMPLE
    .\Get-AcmeDnsCredential.ps1 -ListAll

.NOTES
    Author: Real World Technology Solutions
    Version: 1.0.0
#>

[CmdletBinding(DefaultParameterSetName = 'Single')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Single')]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [Parameter(ParameterSetName = 'Single')]
    [switch]$AsPlainText,

    [Parameter(Mandatory = $true, ParameterSetName = 'List')]
    [switch]$ListAll
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

Initialize-WinCertManager

if ($ListAll) {
    # List all registered domains
    $configPath = Join-Path $env:ProgramData 'WinCertManager\Config\acme-dns'

    if (-not (Test-Path $configPath)) {
        Write-Host 'No acme-dns registrations found.' -ForegroundColor Yellow
        return @()
    }

    $credFiles = Get-ChildItem -Path $configPath -Filter '*.json' | Where-Object { $_.Name -notmatch '\.meta\.json$' }

    if ($credFiles.Count -eq 0) {
        Write-Host 'No acme-dns registrations found.' -ForegroundColor Yellow
        return @()
    }

    Write-Host ''
    Write-Host 'Registered acme-dns domains:' -ForegroundColor Cyan
    Write-Host '========================================' -ForegroundColor Cyan

    $registrations = foreach ($file in $credFiles) {
        try {
            $data = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json

            [PSCustomObject]@{
                Domain = $data.Domain
                Subdomain = $data.Subdomain
                FullDomain = $data.FullDomain
                AcmeDnsServer = $data.AcmeDnsServer
                RegisteredAt = $data.RegisteredAt
                StorageMethod = $data.StorageMethod
            }
        }
        catch {
            Write-Warning "Could not read: $($file.Name)"
        }
    }

    $registrations | Format-Table -AutoSize

    return $registrations
}

# Single domain lookup
$Domain = $Domain.ToLower().Trim()
$credentialFile = Get-SecureCredentialFile -Name $Domain

if (-not (Test-Path $credentialFile)) {
    # Check for metadata file (Credential Manager storage)
    $metadataFile = Get-SecureCredentialFile -Name "$Domain.meta"
    if (Test-Path $metadataFile) {
        $credentialFile = $metadataFile
    }
    else {
        Write-Error "No credentials found for domain '$Domain'. Register with Register-AcmeDns.ps1 first."
        return $null
    }
}

Write-Log "Reading credentials for domain '$Domain'" -Level Verbose

try {
    $storedData = Get-Content -Path $credentialFile -Raw | ConvertFrom-Json
}
catch {
    Write-Error "Failed to read credential file: $($_.Exception.Message)"
    return $null
}

# Determine storage method and retrieve password
$password = $null

switch ($storedData.StorageMethod) {
    'DPAPI' {
        # Decrypt password from DPAPI
        try {
            $securePassword = ConvertTo-SecureString -String $storedData.EncryptedPassword
            if ($AsPlainText) {
                $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
                )
            }
            else {
                $password = $securePassword
            }
        }
        catch {
            Write-Error "Failed to decrypt password. This usually means the credential was stored by a different user or on a different machine."
            return $null
        }
    }

    'CredentialManager' {
        # Retrieve from Windows Credential Manager using secure P/Invoke API
        $targetName = $storedData.CredentialTarget
        try {
            if (-not (Test-WindowsCredentialExists -Target $targetName)) {
                Write-Error "Credential not found in Credential Manager: $targetName"
                return $null
            }

            Write-Log 'Credential exists in Credential Manager' -Level Verbose

            if ($AsPlainText) {
                $credential = Get-WindowsCredential -Target $targetName -AsPlainText
                if ($credential) {
                    $password = $credential.Password
                    # Update username from Credential Manager if different
                    if ($credential.Username -and $credential.Username -ne $storedData.Username) {
                        $storedData.Username = $credential.Username
                    }
                }
                else {
                    Write-Warning 'Could not retrieve credential from Credential Manager'
                    $password = $null
                }
            }
            else {
                $credential = Get-WindowsCredential -Target $targetName
                if ($credential) {
                    $password = $credential.Password  # This is a SecureString
                    $storedData.Username = $credential.UserName
                }
                else {
                    $password = $null
                }
            }
        }
        catch {
            Write-Error "Failed to access Credential Manager: $($_.Exception.Message)"
            return $null
        }
    }

    default {
        Write-Error "Unknown storage method: $($storedData.StorageMethod)"
        return $null
    }
}

# Build result object
$result = [PSCustomObject]@{
    Domain = $storedData.Domain
    AcmeDnsServer = $storedData.AcmeDnsServer
    Subdomain = $storedData.Subdomain
    FullDomain = $storedData.FullDomain
    Username = $storedData.Username
    Password = $password
    AllowFrom = $storedData.AllowFrom
    RegisteredAt = $storedData.RegisteredAt
    StorageMethod = $storedData.StorageMethod
    CnameRecord = "_acme-challenge.$($storedData.Domain)"
    CnameTarget = $storedData.FullDomain
}

# Display summary
Write-Host ''
Write-Host "acme-dns Credentials for: $Domain" -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host "  Server:     $($result.AcmeDnsServer)" -ForegroundColor White
Write-Host "  Subdomain:  $($result.Subdomain)" -ForegroundColor White
Write-Host "  Full Name:  $($result.FullDomain)" -ForegroundColor White
Write-Host "  Username:   $($result.Username)" -ForegroundColor White
Write-Host "  Registered: $($result.RegisteredAt)" -ForegroundColor White
Write-Host ''
Write-Host 'Required CNAME record:' -ForegroundColor Yellow
Write-Host "  $($result.CnameRecord)  CNAME  $($result.CnameTarget)" -ForegroundColor Green
Write-Host ''

return $result
