#Requires -Version 5.1
<#
.SYNOPSIS
    Verifies that a Windows Server is ready for win-acme certificate automation.

.DESCRIPTION
    This script performs a comprehensive check of all prerequisites required
    for win-acme and certificate automation including TLS, .NET, permissions,
    and service availability.

.PARAMETER Detailed
    Shows detailed information for each check.

.PARAMETER Service
    Specify which service to check readiness for: IIS, RDGateway, LDAPS, or All.

.EXAMPLE
    .\Test-ServerReadiness.ps1

.EXAMPLE
    .\Test-ServerReadiness.ps1 -Detailed -Service RDGateway

.NOTES
    Author: Real World Technology Solutions
    Version: 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$Detailed,

    [Parameter()]
    [ValidateSet('IIS', 'RDGateway', 'LDAPS', 'All')]
    [string]$Service = 'All'
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

# Results tracking
$checks = @()

function Add-CheckResult {
    param(
        [string]$Name,
        [string]$Category,
        [bool]$Passed,
        [string]$Message,
        [string]$Details = ''
    )

    $script:checks += [PSCustomObject]@{
        Name = $Name
        Category = $Category
        Passed = $Passed
        Status = if ($Passed) { 'PASS' } else { 'FAIL' }
        Message = $Message
        Details = $Details
    }
}

Write-Host ''
Write-Host '========================================' -ForegroundColor Cyan
Write-Host '    SERVER READINESS CHECK' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''

#region Basic System Checks
Write-Host 'Checking basic system requirements...' -ForegroundColor Yellow

# Administrator privileges
$isAdmin = Test-IsAdministrator
Add-CheckResult -Name 'Administrator Privileges' -Category 'System' -Passed $isAdmin `
    -Message $(if ($isAdmin) { 'Running with administrator privileges' } else { 'Not running as administrator' }) `
    -Details 'Administrator privileges required for certificate operations'

# OS Version
$osInfo = Get-OSVersion
$osSupported = $osInfo.Name -ne 'Unknown'
Add-CheckResult -Name 'Operating System' -Category 'System' -Passed $osSupported `
    -Message "$($osInfo.Caption)" `
    -Details "Build: $($osInfo.BuildNumber), Server 2012 compatibility mode: $($osInfo.Is2012)"

# PowerShell Version
$psVersion = $PSVersionTable.PSVersion
$psSupported = $psVersion.Major -ge 5
Add-CheckResult -Name 'PowerShell Version' -Category 'System' -Passed $psSupported `
    -Message "Version $psVersion" `
    -Details $(if ($psSupported) { 'Meets minimum requirement (5.0+)' } else { 'Upgrade to PowerShell 5.1 recommended' })
#endregion

#region TLS Check
Write-Host 'Checking TLS configuration...' -ForegroundColor Yellow

$tlsEnabled = Test-TLS12Enabled
Add-CheckResult -Name 'TLS 1.2' -Category 'Security' -Passed $tlsEnabled `
    -Message $(if ($tlsEnabled) { 'TLS 1.2 is enabled' } else { 'TLS 1.2 is not properly configured' }) `
    -Details 'Required for ACME protocol communication'

# Test actual HTTPS connectivity
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $testResponse = Invoke-WebRequest -Uri 'https://acme-v02.api.letsencrypt.org/directory' -UseBasicParsing -TimeoutSec 10
    $httpsWorks = $testResponse.StatusCode -eq 200
}
catch {
    $httpsWorks = $false
}
Add-CheckResult -Name 'HTTPS Connectivity' -Category 'Network' -Passed $httpsWorks `
    -Message $(if ($httpsWorks) { 'Can connect to Let''s Encrypt API' } else { 'Cannot reach Let''s Encrypt API' }) `
    -Details 'Tests connectivity to acme-v02.api.letsencrypt.org'
#endregion

#region .NET Framework Check
Write-Host 'Checking .NET Framework...' -ForegroundColor Yellow

$dotNet = Get-DotNetVersion
Add-CheckResult -Name '.NET Framework' -Category 'Runtime' -Passed $dotNet.MeetsMinimum `
    -Message $(if ($dotNet.Installed) { "Version $($dotNet.Version)" } else { 'Not installed' }) `
    -Details $(if ($dotNet.MeetsMinimum) { 'Meets minimum requirement (4.7.2+)' } else { 'Version 4.7.2+ required for win-acme' })
#endregion

#region win-acme Check
Write-Host 'Checking win-acme installation...' -ForegroundColor Yellow

$winAcmePath = Get-WinAcmePath
$winAcmeInstalled = $null -ne $winAcmePath

$winAcmeVersion = ''
if ($winAcmeInstalled) {
    $wacsExe = Join-Path $winAcmePath 'wacs.exe'
    $winAcmeVersion = (Get-Item $wacsExe).VersionInfo.ProductVersion
}

Add-CheckResult -Name 'win-acme Installation' -Category 'Certificate' -Passed $winAcmeInstalled `
    -Message $(if ($winAcmeInstalled) { "Installed at $winAcmePath" } else { 'Not installed' }) `
    -Details $(if ($winAcmeVersion) { "Version: $winAcmeVersion" } else { 'Run Install-Prerequisites.ps1 to install' })

# Check scheduled task
$taskName = 'win-acme renew'
$taskExists = $null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
Add-CheckResult -Name 'Renewal Scheduled Task' -Category 'Certificate' -Passed $taskExists `
    -Message $(if ($taskExists) { 'Scheduled task exists' } else { 'Scheduled task not found' }) `
    -Details "Task name: '$taskName'"
#endregion

#region Service-Specific Checks
if ($Service -in @('IIS', 'All')) {
    Write-Host 'Checking IIS...' -ForegroundColor Yellow

    $iisInstalled = $null -ne (Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue)
    Add-CheckResult -Name 'IIS Service' -Category 'IIS' -Passed $iisInstalled `
        -Message $(if ($iisInstalled) { 'IIS is installed' } else { 'IIS is not installed' }) `
        -Details 'World Wide Web Publishing Service (W3SVC)'

    if ($iisInstalled) {
        # Check if WebAdministration module is available
        $webAdminModule = Get-Module -ListAvailable -Name WebAdministration
        Add-CheckResult -Name 'WebAdministration Module' -Category 'IIS' -Passed ($null -ne $webAdminModule) `
            -Message $(if ($webAdminModule) { 'Module available' } else { 'Module not available' }) `
            -Details 'Required for IIS certificate binding management'
    }
}

if ($Service -in @('RDGateway', 'All')) {
    Write-Host 'Checking RD Gateway...' -ForegroundColor Yellow

    $rdgwInstalled = $null -ne (Get-Service -Name 'TSGateway' -ErrorAction SilentlyContinue)
    Add-CheckResult -Name 'RD Gateway Service' -Category 'RDGateway' -Passed $rdgwInstalled `
        -Message $(if ($rdgwInstalled) { 'RD Gateway is installed' } else { 'RD Gateway is not installed' }) `
        -Details 'Remote Desktop Gateway service (TSGateway)'

    if ($rdgwInstalled) {
        # Check RemoteDesktopServices module
        $rdsModule = Get-Module -ListAvailable -Name RemoteDesktopServices
        Add-CheckResult -Name 'RemoteDesktopServices Module' -Category 'RDGateway' -Passed ($null -ne $rdsModule) `
            -Message $(if ($rdsModule) { 'Module available' } else { 'Module not available' }) `
            -Details 'Required for RD Gateway certificate management'
    }
}

if ($Service -in @('LDAPS', 'All')) {
    Write-Host 'Checking LDAPS/Domain Controller...' -ForegroundColor Yellow

    # Check if this is a domain controller
    $isDC = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
    Add-CheckResult -Name 'Domain Controller' -Category 'LDAPS' -Passed $isDC `
        -Message $(if ($isDC) { 'This is a Domain Controller' } else { 'This is not a Domain Controller' }) `
        -Details 'LDAPS certificate management requires Domain Controller role'

    if ($isDC) {
        # Check NTDS service
        $ntdsRunning = (Get-Service -Name 'NTDS' -ErrorAction SilentlyContinue).Status -eq 'Running'
        Add-CheckResult -Name 'NTDS Service' -Category 'LDAPS' -Passed $ntdsRunning `
            -Message $(if ($ntdsRunning) { 'Active Directory Domain Services running' } else { 'NTDS service not running' }) `
            -Details 'Required for LDAPS'

        # Test LDAPS port
        $ldapsPort = 636
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.Connect('localhost', $ldapsPort)
            $ldapsListening = $tcpClient.Connected
            $tcpClient.Close()
        }
        catch {
            $ldapsListening = $false
        }
        Add-CheckResult -Name 'LDAPS Port (636)' -Category 'LDAPS' -Passed $ldapsListening `
            -Message $(if ($ldapsListening) { 'Port 636 is listening' } else { 'Port 636 is not listening' }) `
            -Details 'LDAPS requires a valid certificate to listen on port 636'
    }
}
#endregion

#region Certificate Store Check
Write-Host 'Checking certificate store...' -ForegroundColor Yellow

$personalCerts = Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue
$certCount = ($personalCerts | Measure-Object).Count
Add-CheckResult -Name 'Certificate Store Access' -Category 'Certificate' -Passed $true `
    -Message "LocalMachine\My store accessible ($certCount certificates)" `
    -Details 'Personal certificate store for machine'

# Check for Let's Encrypt certificates
$leCerts = $personalCerts | Where-Object { $_.Issuer -like "*Let's Encrypt*" -or $_.Issuer -like "*R3*" -or $_.Issuer -like "*R10*" -or $_.Issuer -like "*R11*" }
$leCount = ($leCerts | Measure-Object).Count
if ($leCount -gt 0) {
    Add-CheckResult -Name "Let's Encrypt Certificates" -Category 'Certificate' -Passed $true `
        -Message "$leCount Let's Encrypt certificate(s) found" `
        -Details ($leCerts | ForEach-Object { "$($_.Subject) (Expires: $($_.NotAfter))" }) -join '; '
}
#endregion

#region Summary Output
Write-Host ''
Write-Host '========================================' -ForegroundColor Cyan
Write-Host '         READINESS SUMMARY' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''

$categories = $checks | Select-Object -ExpandProperty Category -Unique

foreach ($category in $categories) {
    $categoryChecks = $checks | Where-Object { $_.Category -eq $category }
    Write-Host "[$category]" -ForegroundColor White

    foreach ($check in $categoryChecks) {
        $statusColor = if ($check.Passed) { 'Green' } else { 'Red' }
        $statusSymbol = if ($check.Passed) { '[OK]' } else { '[!!]' }

        Write-Host "  $statusSymbol " -ForegroundColor $statusColor -NoNewline
        Write-Host "$($check.Name): " -NoNewline
        Write-Host $check.Message

        if ($Detailed -and $check.Details) {
            Write-Host "      Details: $($check.Details)" -ForegroundColor Gray
        }
    }
    Write-Host ''
}

# Overall status
$passedCount = ($checks | Where-Object { $_.Passed }).Count
$totalCount = $checks.Count
$allPassed = $passedCount -eq $totalCount

Write-Host '========================================' -ForegroundColor Cyan
if ($allPassed) {
    Write-Host "  All checks passed ($passedCount/$totalCount)" -ForegroundColor Green
    Write-Host '  Server is ready for certificate automation' -ForegroundColor Green
}
else {
    $failedCount = $totalCount - $passedCount
    Write-Host "  $failedCount of $totalCount checks failed" -ForegroundColor Red
    Write-Host '  Please address the issues above before proceeding' -ForegroundColor Yellow

    Write-Host ''
    Write-Host 'Failed checks:' -ForegroundColor Yellow
    $checks | Where-Object { -not $_.Passed } | ForEach-Object {
        Write-Host "  - $($_.Name): $($_.Message)" -ForegroundColor Red
    }
}
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''

# Return results
[PSCustomObject]@{
    Ready = $allPassed
    PassedCount = $passedCount
    TotalCount = $totalCount
    Checks = $checks
}
#endregion
