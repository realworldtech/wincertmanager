#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Re-encrypts an existing acme-dns credential file under machine-scoped
    DPAPI so the SYSTEM-context win-acme renewal task can decrypt it.

.DESCRIPTION
    When acme-dns credentials are registered via Register-AcmeDns.ps1 from an
    interactive operator session, the password is encrypted with DPAPI in
    CurrentUser scope. The win-acme renewal scheduled task runs as SYSTEM,
    which cannot decrypt CurrentUser-scoped DPAPI blobs. Result: every
    automatic renewal fails until the certificate expires.

    This recovery tool:
      1. Reads the existing credential file for the supplied -Domain.
      2. Prompts for (or accepts) the original acme-dns password.
      3. Re-encrypts the password with DataProtectionScope.LocalMachine, so
         any account on the machine (including SYSTEM) can decrypt it.
      4. Writes the credential file back with StorageMethod set to
         "DPAPI-LocalMachine", preserving all other fields.
      5. Patches the local toolkit's Get-AcmeDnsCredential.ps1 to recognise
         the new StorageMethod (idempotent; backs up first).
      6. Verifies the round-trip by invoking the patched
         Get-AcmeDnsCredential.ps1 and confirming it returns the password.

    The script is self-contained; copy it to any affected host and run as
    Administrator. It does not depend on Common.ps1 or any other toolkit
    helper.

.PARAMETER Domain
    The domain whose credential needs repairing
    (e.g., "dc01.internal.example.com"). Optional: when omitted and the
    credential store contains exactly one registration, that domain is
    auto-detected. If multiple registrations exist, -Domain is required.
    Useful for unattended runs from RMM platforms on hosts that hold a
    single acme-dns credential.

.PARAMETER Password
    SecureString containing the acme-dns password. If omitted, the script
    prompts. The password is the "password" field returned by the acme-dns
    /register endpoint, NOT the registration API key.

.PARAMETER ToolkitPath
    Path to the deployed WinCertManager toolkit directory (the one
    containing scripts\AcmeDns\Get-AcmeDnsCredential.ps1). Auto-detected
    by searching C:\Tools, C:\Program Files, and C:\Program Files (x86)
    if omitted.

.PARAMETER CredentialPath
    Override the credential storage directory. Defaults to
    "$env:ProgramData\WinCertManager\Config\acme-dns".

.PARAMETER SkipToolkitPatch
    Skip updating Get-AcmeDnsCredential.ps1. Use only when a version that
    already understands DPAPI-LocalMachine is deployed.

.PARAMETER SkipVerify
    Skip post-repair verification (decrypting via the patched
    Get-AcmeDnsCredential.ps1).

.EXAMPLE
    .\Repair-AcmeDnsCredential.ps1 -Domain "dc01.internal.example.com"

.EXAMPLE
    $pw = Read-Host -AsSecureString
    .\Repair-AcmeDnsCredential.ps1 -Domain "dc01.example.com" -Password $pw -WhatIf

.EXAMPLE
    # Unattended single-domain host (e.g., from an RMM platform): auto-detects
    # the domain from the credential store and avoids confirmation prompts.
    $pw = ConvertTo-SecureString $env:ACMEDNS_PASSWORD -AsPlainText -Force
    .\Repair-AcmeDnsCredential.ps1 -Password $pw -Confirm:$false

.NOTES
    Author: Real World Technology Solutions
    Version: 1.0.0

    After repair, force a renewal to confirm the fix:
        C:\Tools\win-acme\wacs.exe --renew --force --verbose
#>
[CmdletBinding(SupportsShouldProcess)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CredentialPath',
    Justification = 'CredentialPath is a filesystem path to the credential storage directory, not a password.')]
param(
    [Parameter()]
    [string]$Domain,

    [Parameter()]
    [SecureString]$Password,

    [Parameter()]
    [string]$ToolkitPath,

    [Parameter()]
    [string]$CredentialPath,

    [Parameter()]
    [switch]$SkipToolkitPatch,

    [Parameter()]
    [switch]$SkipVerify
)

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Security

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

function Resolve-DomainFromCredentialStore {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Credential directory not found: $Path. Pass -Domain explicitly or specify -CredentialPath."
    }

    # Exclude .meta.json (Credential Manager metadata) and our own .bak.* backups.
    $files = Get-ChildItem -LiteralPath $Path -Filter '*.json' -File -ErrorAction Stop |
        Where-Object { $_.Name -notmatch '\.meta\.json$' }

    if ($files.Count -eq 0) {
        throw "No acme-dns credential files found in '$Path'. Register a domain with Register-AcmeDns.ps1 first, or pass -Domain to point at a specific file."
    }

    if ($files.Count -gt 1) {
        $list = ($files | ForEach-Object { ' - ' + [System.IO.Path]::GetFileNameWithoutExtension($_.Name) }) -join "`n"
        throw "Multiple acme-dns credentials found in '$Path'. Specify -Domain to choose one:`n$list"
    }

    return [System.IO.Path]::GetFileNameWithoutExtension($files[0].Name)
}

function Find-ToolkitPath {
    [CmdletBinding()]
    param()

    $roots = @('C:\Tools', "$env:ProgramFiles", "${env:ProgramFiles(x86)}") |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    $candidates = foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -Directory -Filter 'wincertmanager*' -ErrorAction SilentlyContinue
    }

    foreach ($candidate in $candidates | Sort-Object LastWriteTime -Descending) {
        $script = Join-Path $candidate.FullName 'scripts\AcmeDns\Get-AcmeDnsCredential.ps1'
        if (Test-Path -LiteralPath $script -PathType Leaf) {
            return $candidate.FullName
        }
    }
    return $null
}

function Invoke-DpapiRoundTrip {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$SecurePassword
    )

    $bstr = [IntPtr]::Zero
    $plainBytes = $null
    $verifyBytes = $null
    try {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($plainText)

        $protected = [System.Security.Cryptography.ProtectedData]::Protect(
            $plainBytes, $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
        $encryptedB64 = [Convert]::ToBase64String($protected)

        # Round-trip verify: decrypt and compare to original plaintext.
        $verifyBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $protected, $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
        $verifyText = [System.Text.Encoding]::UTF8.GetString($verifyBytes)
        if ($verifyText -ne $plainText) {
            throw 'DPAPI round-trip verification failed: decrypted value does not match input.'
        }

        return $encryptedB64
    }
    finally {
        if ($null -ne $plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
        if ($null -ne $verifyBytes) { [Array]::Clear($verifyBytes, 0, $verifyBytes.Length) }
        if ($bstr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Update-GetAcmeDnsCredentialScript {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )

    $scriptText = Get-Content -LiteralPath $ScriptPath -Raw

    if ($scriptText -match 'DPAPI-LocalMachine') {
        Write-Host '  Already patched (DPAPI-LocalMachine case present).' -ForegroundColor Yellow
        return $false
    }

    # Locate the existing 'DPAPI' switch case. The marker matches the file as
    # shipped in the 1.0.x toolkit. If a future version reformats the switch,
    # the patch will be skipped and the operator must apply manually.
    $marker = "    'DPAPI' {"
    $markerIdx = $scriptText.IndexOf($marker)
    if ($markerIdx -lt 0) {
        throw "Could not locate the 'DPAPI' switch case in $ScriptPath. Apply the patch manually or re-deploy the toolkit."
    }

    $newCase = @"
    'DPAPI-LocalMachine' {
        # Decrypt with machine-scoped DPAPI (any user on this host, including SYSTEM).
        try {
            Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
            `$protectedBytes = [Convert]::FromBase64String(`$storedData.EncryptedPassword)
            `$plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
                `$protectedBytes, `$null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
            `$plainText = [System.Text.Encoding]::UTF8.GetString(`$plainBytes)
            [Array]::Clear(`$plainBytes, 0, `$plainBytes.Length)
            if (`$AsPlainText) {
                `$password = `$plainText
            }
            else {
                `$password = ConvertTo-SecureString -String `$plainText -AsPlainText -Force
            }
        }
        catch {
            Write-Error "Failed to decrypt password (LocalMachine DPAPI): `$(`$_.Exception.Message)"
            return `$null
        }
    }


"@

    $patched = $scriptText.Substring(0, $markerIdx) + $newCase + $scriptText.Substring($markerIdx)

    if ($PSCmdlet.ShouldProcess($ScriptPath, 'Patch to support DPAPI-LocalMachine')) {
        $backup = "$ScriptPath.bak.$((Get-Date).ToString('yyyyMMddHHmmss'))"
        Copy-Item -LiteralPath $ScriptPath -Destination $backup -Force
        Set-Content -LiteralPath $ScriptPath -Value $patched -Force
        Write-Host "  Patched. Backup: $backup" -ForegroundColor Green
        return $true
    }

    return $false
}

# -----------------------------------------------------------------------------
# Locate toolkit and credential file
# -----------------------------------------------------------------------------

if (-not $ToolkitPath) {
    $ToolkitPath = Find-ToolkitPath
}

$getCredScript = $null
if ($ToolkitPath) {
    $getCredScript = Join-Path $ToolkitPath 'scripts\AcmeDns\Get-AcmeDnsCredential.ps1'
    if (-not (Test-Path -LiteralPath $getCredScript -PathType Leaf)) {
        throw "Get-AcmeDnsCredential.ps1 not found at: $getCredScript"
    }
}
elseif (-not $SkipToolkitPatch) {
    throw 'Could not auto-detect a WinCertManager toolkit installation. Use -ToolkitPath, or pass -SkipToolkitPatch if the toolkit is already up to date.'
}

if (-not $CredentialPath) {
    $CredentialPath = Join-Path $env:ProgramData 'WinCertManager\Config\acme-dns'
}

if (-not $Domain) {
    $Domain = Resolve-DomainFromCredentialStore -Path $CredentialPath
    Write-Host "Auto-detected domain: $Domain" -ForegroundColor Cyan
}

$normalizedDomain = $Domain.ToLower().Trim()
$credentialFile = Join-Path $CredentialPath ("$normalizedDomain.json")

Write-Host ''
Write-Host '=== WinCertManager acme-dns Credential Repair ===' -ForegroundColor Cyan
Write-Host "Toolkit:         $(if ($ToolkitPath) { $ToolkitPath } else { '(skipped)' })" -ForegroundColor White
Write-Host "Credential file: $credentialFile" -ForegroundColor White
Write-Host ''

if (-not (Test-Path -LiteralPath $credentialFile -PathType Leaf)) {
    throw "Credential file not found: $credentialFile"
}

# -----------------------------------------------------------------------------
# Load and validate credential file
# -----------------------------------------------------------------------------

try {
    $storedData = Get-Content -LiteralPath $credentialFile -Raw | ConvertFrom-Json
}
catch {
    throw "Failed to parse credential file '$credentialFile': $($_.Exception.Message)"
}

$requiredFields = @('Domain', 'AcmeDnsServer', 'Subdomain', 'FullDomain', 'Username')
foreach ($field in $requiredFields) {
    if ($storedData.PSObject.Properties.Name -notcontains $field) {
        throw "Credential file is missing required field '$field'."
    }
}

if ($storedData.StorageMethod -eq 'CredentialManager') {
    throw "StorageMethod is 'CredentialManager'. This script repairs DPAPI-stored credentials only. Re-register the domain or restore manually."
}
elseif ($storedData.StorageMethod -eq 'DPAPI-LocalMachine') {
    Write-Warning "StorageMethod is already 'DPAPI-LocalMachine'. Continuing will overwrite with the supplied password."
}
elseif ($storedData.StorageMethod -ne 'DPAPI') {
    Write-Warning "Unexpected StorageMethod '$($storedData.StorageMethod)'. Continuing anyway."
}

Write-Host "Domain:          $($storedData.Domain)" -ForegroundColor White
Write-Host "Subdomain:       $($storedData.Subdomain)" -ForegroundColor White
Write-Host "Username:        $($storedData.Username)" -ForegroundColor White
Write-Host "Storage method:  $($storedData.StorageMethod)" -ForegroundColor White
Write-Host ''

# -----------------------------------------------------------------------------
# Prompt for password if not supplied
# -----------------------------------------------------------------------------

if (-not $Password) {
    Write-Host "Enter the acme-dns password (the 'password' field from the original /register response):" -ForegroundColor Yellow
    $Password = Read-Host -AsSecureString
}
if (-not $Password -or $Password.Length -eq 0) {
    throw 'Password cannot be empty.'
}

# -----------------------------------------------------------------------------
# Re-encrypt under LocalMachine DPAPI
# -----------------------------------------------------------------------------

Write-Host 'Encrypting password under DPAPI LocalMachine scope...' -ForegroundColor Cyan
$newEncrypted = Invoke-DpapiRoundTrip -SecurePassword $Password
Write-Host 'Round-trip verification: OK' -ForegroundColor Green

# -----------------------------------------------------------------------------
# Patch toolkit Get-AcmeDnsCredential.ps1
# -----------------------------------------------------------------------------

if (-not $SkipToolkitPatch -and $getCredScript) {
    Write-Host ''
    Write-Host "Patching $getCredScript ..." -ForegroundColor Cyan
    $null = Update-GetAcmeDnsCredentialScript -ScriptPath $getCredScript
}

# -----------------------------------------------------------------------------
# Write updated credential file
# -----------------------------------------------------------------------------

$newData = [ordered]@{}
foreach ($prop in $storedData.PSObject.Properties) {
    $newData[$prop.Name] = $prop.Value
}
$newData['EncryptedPassword'] = $newEncrypted
$newData['StorageMethod'] = 'DPAPI-LocalMachine'
$newData['RepairedAt'] = (Get-Date).ToString('o')

$credBackup = "$credentialFile.bak.$((Get-Date).ToString('yyyyMMddHHmmss'))"
if ($PSCmdlet.ShouldProcess($credentialFile, 'Re-encrypt acme-dns credential under LocalMachine DPAPI')) {
    Copy-Item -LiteralPath $credentialFile -Destination $credBackup -Force
    Write-Host ''
    Write-Host "Backup written: $credBackup" -ForegroundColor Yellow

    $newJson = ([PSCustomObject]$newData) | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $credentialFile -Value $newJson -Force
    Write-Host "Credential repaired: $credentialFile" -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# Verify via patched Get-AcmeDnsCredential.ps1
# -----------------------------------------------------------------------------

if (-not $SkipVerify -and -not $WhatIfPreference -and $getCredScript) {
    Write-Host ''
    Write-Host 'Verifying via Get-AcmeDnsCredential.ps1...' -ForegroundColor Cyan
    $verifyResult = & $getCredScript -Domain $normalizedDomain -AsPlainText 6>$null 5>$null 4>$null 3>$null
    if (-not $verifyResult -or -not $verifyResult.Password) {
        throw 'Verification failed: Get-AcmeDnsCredential.ps1 did not return a password. Inspect manually.'
    }
    Write-Host 'Verification OK: credential decrypts via Get-AcmeDnsCredential.ps1.' -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# Next steps
# -----------------------------------------------------------------------------

Write-Host ''
Write-Host 'Next steps:' -ForegroundColor Cyan
Write-Host '  1. Force a renewal:'
Write-Host '       C:\Tools\win-acme\wacs.exe --renew --force --verbose' -ForegroundColor White
Write-Host '  2. Confirm LDAPS is presenting the new certificate:'
Write-Host '       Test-NetConnection localhost -Port 636' -ForegroundColor White
Write-Host ''
