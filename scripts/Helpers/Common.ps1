#Requires -Version 5.1
<#
.SYNOPSIS
    Common helper functions for Windows Certificate Manager Toolkit.

.DESCRIPTION
    Shared functions used across all scripts in the toolkit including logging,
    certificate operations, and utility functions.

.NOTES
    Author: Real World Technology Solutions
    Version: 1.0.0
#>

# Script-level variables
$script:LogPath = Join-Path $env:ProgramData 'WinCertManager\Logs'
$script:ConfigPath = Join-Path $env:ProgramData 'WinCertManager\Config'

function Initialize-WinCertManager {
    <#
    .SYNOPSIS
        Initializes the WinCertManager environment.

    .DESCRIPTION
        Creates necessary directories and sets up logging.
    #>
    [CmdletBinding()]
    param()

    # Create directories if they don't exist
    $directories = @(
        $script:LogPath,
        $script:ConfigPath,
        (Join-Path $script:ConfigPath 'acme-dns')
    )

    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            Write-Verbose "Created directory: $dir"
        }
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log entry to file and optionally to console.

    .PARAMETER Message
        The message to log.

    .PARAMETER Level
        The log level (Info, Warning, Error, Verbose).

    .PARAMETER LogFile
        Optional specific log file name. Defaults to daily log.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '',
        Justification = 'Write-Log is not a built-in cmdlet in Windows PowerShell 5.1 which this targets')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Verbose')]
        [string]$Level = 'Info',

        [Parameter()]
        [string]$LogFile
    )

    Initialize-WinCertManager

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"

    # Determine log file path
    if (-not $LogFile) {
        $LogFile = "wincertmanager-$(Get-Date -Format 'yyyy-MM-dd').log"
    }
    $logFilePath = Join-Path $script:LogPath $LogFile

    # Write to log file
    Add-Content -Path $logFilePath -Value $logEntry -ErrorAction SilentlyContinue

    # Write to console based on level
    switch ($Level) {
        'Error'   { Write-Error $Message }
        'Warning' { Write-Warning $Message }
        'Verbose' { Write-Verbose $Message }
        default   { Write-Host $Message }
    }

    # Also write to Windows Event Log for important events
    if ($Level -in @('Error', 'Warning')) {
        $eventType = if ($Level -eq 'Error') { 'Error' } else { 'Warning' }
        try {
            # Create event source if it doesn't exist
            if (-not [System.Diagnostics.EventLog]::SourceExists('WinCertManager')) {
                [System.Diagnostics.EventLog]::CreateEventSource('WinCertManager', 'Application')
            }
            Write-EventLog -LogName Application -Source 'WinCertManager' -EventId 1000 -EntryType $eventType -Message $Message -ErrorAction SilentlyContinue
        }
        catch {
            # Silently continue if event log writing fails (e.g., insufficient permissions)
            Write-Verbose "Could not write to event log: $($_.Exception.Message)"
        }
    }
}

function Get-OSVersion {
    <#
    .SYNOPSIS
        Gets the Windows Server version information.

    .OUTPUTS
        PSCustomObject with Version, Name, and BuildNumber properties.
    #>
    [CmdletBinding()]
    param()

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $version = [System.Environment]::OSVersion.Version

    $versionName = switch -Regex ($os.Caption) {
        '2012 R2' { 'Server2012R2' }
        '2012'    { 'Server2012' }
        '2016'    { 'Server2016' }
        '2019'    { 'Server2019' }
        '2022'    { 'Server2022' }
        '2025'    { 'Server2025' }
        default   { 'Unknown' }
    }

    [PSCustomObject]@{
        Version     = $version
        Name        = $versionName
        Caption     = $os.Caption
        BuildNumber = $os.BuildNumber
        Is2012      = $versionName -in @('Server2012', 'Server2012R2')
    }
}

function Test-TLS12Enabled {
    <#
    .SYNOPSIS
        Tests if TLS 1.2 is enabled on the system.

    .OUTPUTS
        Boolean indicating if TLS 1.2 is properly configured.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $clientPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
    $serverPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'

    $clientEnabled = $false
    $serverEnabled = $false

    # Check client
    if (Test-Path $clientPath) {
        $clientSettings = Get-ItemProperty -Path $clientPath -ErrorAction SilentlyContinue
        $clientEnabled = ($clientSettings.Enabled -eq 1) -or ($null -eq $clientSettings.Enabled -and $clientSettings.DisabledByDefault -ne 1)
    }

    # Check server
    if (Test-Path $serverPath) {
        $serverSettings = Get-ItemProperty -Path $serverPath -ErrorAction SilentlyContinue
        $serverEnabled = ($serverSettings.Enabled -eq 1) -or ($null -eq $serverSettings.Enabled -and $serverSettings.DisabledByDefault -ne 1)
    }

    # On newer systems, TLS 1.2 is enabled by default even without registry keys
    $osVersion = Get-OSVersion
    if (-not $osVersion.Is2012) {
        return $true
    }

    return $clientEnabled -and $serverEnabled
}

function Enable-TLS12 {
    <#
    .SYNOPSIS
        Enables TLS 1.2 via registry settings.

    .DESCRIPTION
        Creates necessary registry keys to enable TLS 1.2 on older Windows versions.
        A reboot is required for changes to take effect.

    .PARAMETER WhatIf
        Shows what would happen without making changes.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $protocols = @(
        @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
            Settings = @{
                Enabled = 1
                DisabledByDefault = 0
            }
        },
        @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
            Settings = @{
                Enabled = 1
                DisabledByDefault = 0
            }
        }
    )

    foreach ($protocol in $protocols) {
        if ($PSCmdlet.ShouldProcess($protocol.Path, 'Enable TLS 1.2')) {
            # Create path if it doesn't exist
            if (-not (Test-Path $protocol.Path)) {
                New-Item -Path $protocol.Path -Force | Out-Null
            }

            # Set values
            foreach ($setting in $protocol.Settings.GetEnumerator()) {
                Set-ItemProperty -Path $protocol.Path -Name $setting.Key -Value $setting.Value -Type DWord
            }
        }
    }

    # Also ensure .NET uses strong crypto
    $netFrameworkPaths = @(
        'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    )

    foreach ($path in $netFrameworkPaths) {
        if (Test-Path $path) {
            if ($PSCmdlet.ShouldProcess($path, 'Enable Strong Crypto')) {
                Set-ItemProperty -Path $path -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
            }
        }
    }

    Write-Log 'TLS 1.2 registry settings configured. A reboot is required for changes to take effect.' -Level Warning
}

function Get-DotNetVersion {
    <#
    .SYNOPSIS
        Gets the installed .NET Framework version.

    .OUTPUTS
        PSCustomObject with Version and Release properties.
    #>
    [CmdletBinding()]
    param()

    $ndpPath = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'

    if (-not (Test-Path $ndpPath)) {
        return [PSCustomObject]@{
            Version = $null
            Release = 0
            Installed = $false
        }
    }

    $release = (Get-ItemProperty -Path $ndpPath -Name Release -ErrorAction SilentlyContinue).Release

    # Map release number to version
    $version = switch ($release) {
        { $_ -ge 533320 } { '4.8.1' }
        { $_ -ge 528040 } { '4.8' }
        { $_ -ge 461808 } { '4.7.2' }
        { $_ -ge 461308 } { '4.7.1' }
        { $_ -ge 460798 } { '4.7' }
        { $_ -ge 394802 } { '4.6.2' }
        { $_ -ge 394254 } { '4.6.1' }
        { $_ -ge 393295 } { '4.6' }
        { $_ -ge 379893 } { '4.5.2' }
        { $_ -ge 378675 } { '4.5.1' }
        { $_ -ge 378389 } { '4.5' }
        default { 'Unknown' }
    }

    [PSCustomObject]@{
        Version = $version
        Release = $release
        Installed = $true
        MeetsMinimum = $release -ge 461808  # 4.7.2
    }
}

function Get-CertificateByThumbprint {
    <#
    .SYNOPSIS
        Finds a certificate by thumbprint in the certificate store.

    .PARAMETER Thumbprint
        The certificate thumbprint to search for.

    .PARAMETER StoreName
        The store name to search (default: My).

    .PARAMETER StoreLocation
        The store location (default: LocalMachine).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumbprint,

        [Parameter()]
        [string]$StoreName = 'My',

        [Parameter()]
        [ValidateSet('LocalMachine', 'CurrentUser')]
        [string]$StoreLocation = 'LocalMachine'
    )

    $certPath = "Cert:\$StoreLocation\$StoreName\$Thumbprint"

    if (Test-Path $certPath) {
        return Get-Item $certPath
    }

    return $null
}

function Get-CertificateBySubject {
    <#
    .SYNOPSIS
        Finds certificates by subject name in the certificate store.

    .PARAMETER Subject
        The subject name to search for (partial match).

    .PARAMETER StoreName
        The store name to search (default: My).

    .PARAMETER StoreLocation
        The store location (default: LocalMachine).

    .PARAMETER Latest
        If specified, returns only the most recent certificate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Subject,

        [Parameter()]
        [string]$StoreName = 'My',

        [Parameter()]
        [ValidateSet('LocalMachine', 'CurrentUser')]
        [string]$StoreLocation = 'LocalMachine',

        [Parameter()]
        [switch]$Latest
    )

    $storePath = "Cert:\$StoreLocation\$StoreName"
    $certs = Get-ChildItem -Path $storePath | Where-Object { $_.Subject -like "*$Subject*" }

    if ($Latest -and $certs) {
        return $certs | Sort-Object NotAfter -Descending | Select-Object -First 1
    }

    return $certs
}

function Test-CertificateValid {
    <#
    .SYNOPSIS
        Tests if a certificate is valid (not expired, has private key).

    .PARAMETER Certificate
        The certificate object to test.

    .PARAMETER RequirePrivateKey
        If specified, requires the certificate to have a private key.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter()]
        [switch]$RequirePrivateKey
    )

    $now = Get-Date

    $isValid = $true
    $issues = @()

    # Check validity period
    if ($now -lt $Certificate.NotBefore) {
        $isValid = $false
        $issues += "Certificate is not yet valid (NotBefore: $($Certificate.NotBefore))"
    }

    if ($now -gt $Certificate.NotAfter) {
        $isValid = $false
        $issues += "Certificate has expired (NotAfter: $($Certificate.NotAfter))"
    }

    # Check private key
    if ($RequirePrivateKey -and -not $Certificate.HasPrivateKey) {
        $isValid = $false
        $issues += 'Certificate does not have a private key'
    }

    [PSCustomObject]@{
        IsValid = $isValid
        Issues = $issues
        DaysUntilExpiry = ($Certificate.NotAfter - $now).Days
        Thumbprint = $Certificate.Thumbprint
        Subject = $Certificate.Subject
    }
}

function Get-WinAcmePath {
    <#
    .SYNOPSIS
        Gets the win-acme installation path.

    .OUTPUTS
        The path to win-acme installation or $null if not found.
    #>
    [CmdletBinding()]
    param()

    $possiblePaths = @(
        'C:\Tools\win-acme',
        'C:\Program Files\win-acme',
        "$env:ProgramFiles\win-acme",
        "$env:LOCALAPPDATA\win-acme"
    )

    foreach ($path in $possiblePaths) {
        $wacs = Join-Path $path 'wacs.exe'
        if (Test-Path $wacs) {
            return $path
        }
    }

    return $null
}

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Tests if the current session has administrator privileges.
    #>
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Invokes a script block with retry logic.

    .PARAMETER ScriptBlock
        The script block to execute.

    .PARAMETER MaxRetries
        Maximum number of retry attempts.

    .PARAMETER DelaySeconds
        Delay between retries in seconds.

    .PARAMETER Description
        Description for logging purposes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [int]$MaxRetries = 3,

        [Parameter()]
        [int]$DelaySeconds = 5,

        [Parameter()]
        [string]$Description = 'Operation'
    )

    $attempt = 0
    $lastError = $null

    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $result = & $ScriptBlock
            return $result
        }
        catch {
            $lastError = $_
            Write-Log "$Description failed (attempt $attempt of $MaxRetries): $($_.Exception.Message)" -Level Warning

            if ($attempt -lt $MaxRetries) {
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }

    Write-Log "$Description failed after $MaxRetries attempts: $($lastError.Exception.Message)" -Level Error
    throw $lastError
}

function ConvertTo-SecureCredential {
    <#
    .SYNOPSIS
        Converts a plain text password to a secure string.

    .DESCRIPTION
        This function is used for DPAPI encryption where the plaintext
        is immediately encrypted and stored. The plaintext is not logged
        or persisted in an insecure manner.

    .PARAMETER PlainText
        The plain text to convert.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Required for DPAPI encryption of credentials received from API')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PlainText
    )

    return ConvertTo-SecureString -String $PlainText -AsPlainText -Force
}

function Get-SecureCredentialFile {
    <#
    .SYNOPSIS
        Gets the path to a secure credential file.

    .PARAMETER Name
        The name of the credential file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    Initialize-WinCertManager
    return Join-Path (Join-Path $script:ConfigPath 'acme-dns') "$Name.json"
}

# Export functions
Export-ModuleMember -Function @(
    'Initialize-WinCertManager',
    'Write-Log',
    'Get-OSVersion',
    'Test-TLS12Enabled',
    'Enable-TLS12',
    'Get-DotNetVersion',
    'Get-CertificateByThumbprint',
    'Get-CertificateBySubject',
    'Test-CertificateValid',
    'Get-WinAcmePath',
    'Test-IsAdministrator',
    'Invoke-WithRetry',
    'ConvertTo-SecureCredential',
    'Get-SecureCredentialFile'
)
