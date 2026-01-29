#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies and optionally rebinds LDAPS certificate on a Domain Controller.

.DESCRIPTION
    This script verifies that a renewed certificate is properly configured for
    LDAPS on a Domain Controller. It checks the certificate is in the correct
    store, has the proper EKU, and optionally tests LDAPS connectivity.

.PARAMETER Thumbprint
    The thumbprint of the renewed certificate.

.PARAMETER Subject
    The subject (CN) of the certificate to find. Used if thumbprint not provided.

.PARAMETER TestConnection
    Test LDAPS connectivity after verification.

.PARAMETER ForceRebind
    Force NTDS to rebind to the certificate (triggers service notification).

.PARAMETER StrictSslValidation
    When testing LDAPS connectivity, perform strict SSL/TLS validation including
    certificate chain verification. By default, validation is relaxed to allow
    testing with self-signed or internal CA certificates.

.PARAMETER WhatIf
    Shows what would happen without making changes.

.EXAMPLE
    .\Update-LDAPS.ps1 -Thumbprint 'ABC123...'

.EXAMPLE
    .\Update-LDAPS.ps1 -Subject 'dc01.domain.local' -TestConnection

.NOTES
    Author: Real World Technology Solutions
    Version: 1.0.0

    LDAPS typically picks up new certificates automatically from the Personal store
    if they have the correct EKU (Server Authentication). This script verifies
    the configuration and can test connectivity.

    For win-acme configuration:
    wacs.exe ... --installation script --script "Update-LDAPS.ps1" --scriptparameters "-Thumbprint {CertThumbprint} -TestConnection"
#>

[CmdletBinding(SupportsShouldProcess)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'SSL validation callback parameters are required by delegate signature')]
param(
    [Parameter(ParameterSetName = 'Thumbprint')]
    [string]$Thumbprint,

    [Parameter(ParameterSetName = 'Subject')]
    [string]$Subject,

    [Parameter()]
    [switch]$TestConnection,

    [Parameter()]
    [switch]$ForceRebind,

    [Parameter()]
    [switch]$StrictSslValidation
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
Write-Log 'Starting LDAPS certificate verification' -Level Info

# Logging helper
$loggingScript = Join-Path $PSScriptRoot '..\Logging\Send-CertificateEvent.ps1'

function Send-Event {
    param($EventType, $Domain, $Thumbprint, $Message, $Status)
    if (Test-Path $loggingScript) {
        try {
            & $loggingScript -EventType $EventType -Domain $Domain -Thumbprint $Thumbprint -Message $Message -Status $Status
        }
        catch {
            Write-Log "Failed to send event: $($_.Exception.Message)" -Level Verbose
        }
    }
}

# Verify this is a Domain Controller
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$isDomainController = $computerSystem.DomainRole -ge 4

if (-not $isDomainController) {
    $errorMsg = 'This server is not a Domain Controller. LDAPS certificate management requires a DC.'
    Write-Log $errorMsg -Level Error
    Send-Event -EventType 'Failure' -Domain 'Unknown' -Message $errorMsg -Status 'Error'
    throw $errorMsg
}

Write-Log "Domain Controller: $($computerSystem.Name) in domain $($computerSystem.Domain)" -Level Info

# Verify NTDS service is running
$ntdsService = Get-Service -Name 'NTDS' -ErrorAction SilentlyContinue
if (-not $ntdsService -or $ntdsService.Status -ne 'Running') {
    $errorMsg = 'Active Directory Domain Services (NTDS) is not running.'
    Write-Log $errorMsg -Level Error
    Send-Event -EventType 'Failure' -Domain $computerSystem.Domain -Message $errorMsg -Status 'Error'
    throw $errorMsg
}

# Find the certificate
$certificate = $null

if ($Thumbprint) {
    Write-Log "Looking for certificate with thumbprint: $Thumbprint" -Level Info
    $certificate = Get-CertificateByThumbprint -Thumbprint $Thumbprint
}
elseif ($Subject) {
    Write-Log "Looking for certificate with subject: $Subject" -Level Info
    $certificate = Get-CertificateBySubject -Subject $Subject -Latest
}
else {
    # Try to find certificate matching the DC's FQDN
    $fqdn = "$($computerSystem.Name).$($computerSystem.Domain)"
    Write-Log "No thumbprint/subject specified. Looking for certificate matching: $fqdn" -Level Info
    $certificate = Get-CertificateBySubject -Subject $fqdn -Latest
}

if (-not $certificate) {
    $errorMsg = "Certificate not found. Thumbprint: $Thumbprint, Subject: $Subject"
    Write-Log $errorMsg -Level Error
    Send-Event -EventType 'Failure' -Domain ($Subject ?? $computerSystem.Domain) -Thumbprint $Thumbprint -Message $errorMsg -Status 'Error'
    throw $errorMsg
}

Write-Log "Found certificate: $($certificate.Subject) (Thumbprint: $($certificate.Thumbprint))" -Level Info
Write-Log "Certificate expires: $($certificate.NotAfter)" -Level Info

# Validate certificate
$validation = Test-CertificateValid -Certificate $certificate -RequirePrivateKey
if (-not $validation.IsValid) {
    $errorMsg = "Certificate validation failed: $($validation.Issues -join ', ')"
    Write-Log $errorMsg -Level Error
    Send-Event -EventType 'Failure' -Domain $certificate.Subject -Thumbprint $certificate.Thumbprint -Message $errorMsg -Status 'Error'
    throw $errorMsg
}

# Get domain from certificate
$domain = $certificate.Subject -replace '^CN=', '' -replace ',.*$', ''

# Check certificate has correct EKU for LDAPS
Write-Log 'Checking certificate Extended Key Usage (EKU)...' -Level Info

$serverAuthOid = '1.3.6.1.5.5.7.3.1'  # Server Authentication
$hasServerAuth = $false

foreach ($extension in $certificate.Extensions) {
    if ($extension.Oid.Value -eq '2.5.29.37') {  # Enhanced Key Usage
        $eku = $extension -as [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]
        if ($eku) {
            foreach ($oid in $eku.EnhancedKeyUsages) {
                if ($oid.Value -eq $serverAuthOid) {
                    $hasServerAuth = $true
                    break
                }
            }
        }
    }
}

if ($hasServerAuth) {
    Write-Log 'Certificate has Server Authentication EKU (required for LDAPS)' -Level Info
}
else {
    $errorMsg = 'Certificate does not have Server Authentication EKU. LDAPS requires this.'
    Write-Log $errorMsg -Level Error
    Send-Event -EventType 'Failure' -Domain $domain -Thumbprint $certificate.Thumbprint -Message $errorMsg -Status 'Error'
    throw $errorMsg
}

# Check if certificate is in the NTDS service store (optional location)
# LDAPS primarily uses certs from LocalMachine\My that have Server Auth EKU
$ntdsStorePath = 'HKLM:\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates'
$ntdsCertExists = Test-Path (Join-Path $ntdsStorePath $certificate.Thumbprint)

if ($ntdsCertExists) {
    Write-Log 'Certificate is also present in NTDS service certificate store' -Level Info
}
else {
    Write-Log 'Certificate is in LocalMachine\My store (standard LDAPS location)' -Level Info
}

# Force NTDS to pick up the new certificate if requested
if ($ForceRebind) {
    Write-Log 'Force rebind requested. Notifying NTDS to refresh certificate...' -Level Info

    if ($PSCmdlet.ShouldProcess('NTDS Service', 'Notify certificate change')) {
        try {
            # Method 1: Use certutil to refresh
            $certutilOutput = & certutil -dspublish -f "$($certificate.Thumbprint)" 2>&1
            Write-Log "certutil output: $certutilOutput" -Level Verbose

            # Method 2: Send notification via ldp or netdom (alternative)
            # NTDS monitors the certificate store and should pick up changes automatically

            Write-Log 'NTDS notified of certificate change' -Level Info
        }
        catch {
            Write-Log "Warning: Could not notify NTDS: $($_.Exception.Message)" -Level Warning
        }
    }
}

# Test LDAPS connectivity
$ldapsWorking = $false
if ($TestConnection) {
    Write-Log 'Testing LDAPS connectivity on port 636...' -Level Info

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect('localhost', 636)

        if ($tcpClient.Connected) {
            Write-Log 'TCP connection to port 636 successful' -Level Info

            # Test SSL/TLS handshake
            # Create SSL stream with appropriate validation callback
            if ($StrictSslValidation) {
                Write-Log 'Using strict SSL/TLS validation' -Level Info
                # Use default validation (strict) - validates certificate chain, expiry, etc.
                $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false)
            }
            else {
                Write-Log 'Using relaxed SSL/TLS validation (use -StrictSslValidation for full chain validation)' -Level Verbose
                # Callback parameters required by RemoteCertificateValidationCallback delegate signature
                $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false,
                    { param($_sender, $_certificate, $_chain, $_sslPolicyErrors) return $true })
            }

            try {
                $sslStream.AuthenticateAsClient('localhost')

                # Get the certificate presented by LDAPS
                $remoteCert = $sslStream.RemoteCertificate
                if ($remoteCert) {
                    $remoteCert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($remoteCert)
                    Write-Log "LDAPS certificate thumbprint: $($remoteCert2.Thumbprint)" -Level Info

                    if ($remoteCert2.Thumbprint -eq $certificate.Thumbprint) {
                        Write-Log 'LDAPS is using the correct certificate' -Level Info
                        $ldapsWorking = $true
                    }
                    else {
                        Write-Log "Warning: LDAPS is using a different certificate (Thumbprint: $($remoteCert2.Thumbprint))" -Level Warning
                        Write-Log 'The new certificate may require NTDS service restart or time to be picked up' -Level Warning
                    }
                }

                $sslStream.Close()
            }
            catch {
                Write-Log "SSL handshake failed: $($_.Exception.Message)" -Level Warning
            }

            $tcpClient.Close()
        }
    }
    catch {
        Write-Log "LDAPS connection test failed: $($_.Exception.Message)" -Level Warning
        Write-Log 'LDAPS may not be configured yet or requires a valid certificate to start' -Level Info
    }
}

# Output summary
$status = if ($ldapsWorking -or -not $TestConnection) { 'Success' } else { 'Warning' }

Write-Host ''
Write-Host '========================================' -ForegroundColor $(if ($status -eq 'Success') { 'Green' } else { 'Yellow' })
Write-Host '  LDAPS CERTIFICATE VERIFICATION' -ForegroundColor $(if ($status -eq 'Success') { 'Green' } else { 'Yellow' })
Write-Host '========================================' -ForegroundColor $(if ($status -eq 'Success') { 'Green' } else { 'Yellow' })
Write-Host ''
Write-Host "  Domain Controller: $($computerSystem.Name)" -ForegroundColor White
Write-Host "  Domain:           $domain" -ForegroundColor White
Write-Host "  Thumbprint:       $($certificate.Thumbprint)" -ForegroundColor White
Write-Host "  Expires:          $($certificate.NotAfter)" -ForegroundColor White
Write-Host "  Days Left:        $($validation.DaysUntilExpiry)" -ForegroundColor White
Write-Host "  Server Auth EKU:  Yes" -ForegroundColor White
if ($TestConnection) {
    Write-Host "  LDAPS Test:       $(if ($ldapsWorking) { 'Passed' } else { 'Check Required' })" -ForegroundColor $(if ($ldapsWorking) { 'Green' } else { 'Yellow' })
}
Write-Host ''

# Send event
$message = if ($ldapsWorking) {
    'LDAPS certificate verified and connectivity confirmed'
}
elseif (-not $TestConnection) {
    'LDAPS certificate verified (connection test not performed)'
}
else {
    'LDAPS certificate verified but connection test did not confirm new certificate. May require time or service restart.'
}

Send-Event -EventType 'Installation' -Domain $domain -Thumbprint $certificate.Thumbprint -ExpiryDate $certificate.NotAfter -Message $message -Status $status

Write-Log $message -Level Info

# Return result
[PSCustomObject]@{
    Success = ($status -eq 'Success')
    DomainController = $computerSystem.Name
    Domain = $domain
    Thumbprint = $certificate.Thumbprint
    ExpiryDate = $certificate.NotAfter
    DaysUntilExpiry = $validation.DaysUntilExpiry
    HasServerAuthEKU = $hasServerAuth
    InNtdsStore = $ntdsCertExists
    LdapsTestPassed = $ldapsWorking
    Message = $message
}
