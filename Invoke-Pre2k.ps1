<#
.SYNOPSIS
    Tests all Active Directory computer accounts for pre-Windows 2000 weak authentication.

.DESCRIPTION
    Queries Active Directory for ALL computer accounts and tests for weak authentication
    commonly found in pre-Windows 2000 compatible accounts, using empty passwords or
    passwords matching the lowercase machine name (first 14 characters).

.PARAMETER EmptyPasswordOnly
    Only test empty passwords for discovered accounts.

.PARAMETER MachineNameOnly
    Only test passwords matching the lowercase machine name.

.PARAMETER Username
    Optional custom username for authentication tests. If not specified, uses current user context.

.PARAMETER Password
    Optional custom password (SecureString) for authentication tests.

.PARAMETER Domain
    Optional custom domain. If not specified, uses the current user's domain.

.EXAMPLE
    .\Invoke-Pre2k.ps1
    Scans ALL computers in the current domain using both empty and machine name passwords.

.EXAMPLE
    .\Invoke-Pre2k.ps1 -EmptyPasswordOnly
    Only tests empty passwords on all computer accounts.

.EXAMPLE
    .\Invoke-Pre2k.ps1 -MachineNameOnly
    Only tests passwords matching the lowercase machine name.

.EXAMPLE
    .\Invoke-Pre2k.ps1 -Domain "contoso.com"
    Scans the specified domain for vulnerable computer accounts.

.NOTES
    Requires network access to Active Directory and sufficient permissions to query computer objects.
    Uses only ADSI and System.DirectoryServices classes - no external modules required.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$EmptyPasswordOnly,

    [Parameter(Mandatory=$false)]
    [switch]$MachineNameOnly,

    [Parameter(Mandatory=$false)]
    [string]$Username,

    [Parameter(Mandatory=$false)]
    [SecureString]$Password,

    [Parameter(Mandatory=$false)]
    [string]$Domain,

    [Parameter(Mandatory=$false)]
    [int]$TimeoutSeconds = 10
)

#Requires -Version 3.0

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Validate mutually exclusive parameters
if ($EmptyPasswordOnly -and $MachineNameOnly) {
    Write-Host "[!] ERROR: Cannot specify both -EmptyPasswordOnly and -MachineNameOnly" -ForegroundColor Red
    exit 1
}

# Validate Username and Password are used together
if (($Username -and -not $Password) -or ($Password -and -not $Username)) {
    Write-Host "[!] ERROR: -Username and -Password must be specified together" -ForegroundColor Red
    exit 1
}

function Get-DomainPath {
    param(
        [string]$DomainName,
        [string]$Username,
        [System.Security.SecureString]$Password
    )

    try {
        if ([string]::IsNullOrWhiteSpace($DomainName)) {
            # Get current domain
            if ($Username -and $Password) {
                $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
                try {
                    $passwordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                    $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE", $Username, $passwordPlain)
                } finally {
                    # Zero out password from memory
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                }
            } else {
                $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
            }
            $domainDN = $rootDSE.defaultNamingContext.Value
            $domainPath = "LDAP://$domainDN"
            $rootDSE.Dispose()
        } else {
            # Convert domain name to DN format
            $domainDN = "DC=" + ($DomainName -replace "\.", ",DC=")
            $domainPath = "LDAP://$domainDN"
        }

        return $domainPath
    } catch {
        Write-Host "[!] ERROR: Failed to determine domain path: $_" -ForegroundColor Red
        exit 1
    }
}

function Get-Pre2kComputers {
    param(
        [string]$DomainPath,
        [string]$Username,
        [System.Security.SecureString]$Password
    )

    $computers = @()

    try {
        Write-Host "[*] Querying domain for computer accounts..." -ForegroundColor Cyan

        if ($Username -and $Password) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            try {
                $passwordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($DomainPath, $Username, $passwordPlain)
                Write-Verbose "Using custom credentials for domain query: $Username"
            } finally {
                # Zero out password from memory
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        } else {
            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($DomainPath)
            Write-Verbose "Using current user context for domain query"
        }

        $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)

        # LDAP filter for ALL computer accounts
        # Pre-Windows 2000 compatible computers don't have a reliable flag - we must test all computers
        $searcher.Filter = "(&(objectCategory=computer)(objectClass=computer))"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@("sAMAccountName", "dNSHostName", "userAccountControl"))

        $results = $searcher.FindAll()

        foreach ($result in $results) {
            $samAccountName = $result.Properties["sAMAccountName"][0]
            $dnsHostName = if ($result.Properties["dNSHostName"].Count -gt 0) {
                $result.Properties["dNSHostName"][0]
            } else {
                $null
            }
            $uac = $result.Properties["userAccountControl"][0]

            $computers += [PSCustomObject]@{
                SAMAccountName = $samAccountName
                DNSHostName = $dnsHostName
                UserAccountControl = $uac
            }
        }

        # Dispose resources
        $results.Dispose()
        $searcher.Dispose()
        $directoryEntry.Dispose()

        Write-Host "[+] Found $($computers.Count) computer accounts" -ForegroundColor Green

        return $computers
    } catch {
        Write-Host "[!] ERROR: Failed to query domain: $_" -ForegroundColor Red
        Write-Verbose "Exception details: $($_.Exception.Message)"
        exit 1
    }
}

function Test-Authentication {
    param(
        [string]$DomainPath,
        [string]$Username,
        [string]$Password,
        [int]$TimeoutSeconds = 10
    )

    try {
        # Use a job for timeout support (compatible with PS 3.0+)
        $job = Start-Job -ScriptBlock {
            param($path, $user, $pass)
            try {
                $entry = New-Object System.DirectoryServices.DirectoryEntry($path, $user, $pass)
                $entry.AuthenticationType = [System.DirectoryServices.AuthenticationTypes]::Secure
                $null = $entry.NativeObject
                $entry.Dispose()
                return $true
            } catch {
                return $false
            }
        } -ArgumentList $DomainPath, $Username, $Password

        # Wait for job with timeout
        $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds

        if ($null -eq $completed) {
            Write-Verbose "Authentication timeout for user: $Username"
            Stop-Job -Job $job
            Remove-Job -Job $job -Force
            return $false
        }

        $result = Receive-Job -Job $job
        Remove-Job -Job $job -Force

        return $result

    } catch [System.Runtime.InteropServices.COMException] {
        # Authentication failed - expected for most accounts
        Write-Verbose "Authentication failed (COMException) for user: $Username"
        return $false
    } catch {
        # Other errors (network issues, etc.)
        Write-Verbose "Authentication failed with error: $($_.Exception.Message)"
        return $false
    }
}

function Test-Credentials {
    param(
        [string]$DomainPath,
        [string]$Username,
        [System.Security.SecureString]$Password
    )

    try {
        Write-Host "[*] Validating custom credentials..." -ForegroundColor Cyan

        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        try {
            $passwordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($DomainPath, $Username, $passwordPlain)

            # Attempt to bind
            $null = $directoryEntry.NativeObject
            $directoryEntry.Dispose()

            Write-Host "[+] Credentials validated successfully" -ForegroundColor Green
            return $true
        } finally {
            # Zero out password from memory
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    } catch {
        Write-Host "[!] ERROR: Failed to validate custom credentials: $_" -ForegroundColor Red
        Write-Host "[!] Ensure the username and password are correct and have domain access" -ForegroundColor Red
        return $false
    }
}

function Get-MachinePassword {
    param(
        [string]$SAMAccountName
    )

    # Remove trailing $ if present
    $machineName = $SAMAccountName.TrimEnd('$')

    # Take first 14 characters and convert to lowercase
    $machinePassword = $machineName.Substring(0, [Math]::Min(14, $machineName.Length)).ToLower()

    return $machinePassword
}

# Main execution
try {
    Write-Verbose "Script started with parameters:"
    Write-Verbose "  Domain: $(if ($Domain) { $Domain } else { 'Current domain' })"
    Write-Verbose "  Username: $(if ($Username) { $Username } else { 'Current user' })"
    Write-Verbose "  EmptyPasswordOnly: $EmptyPasswordOnly"
    Write-Verbose "  MachineNameOnly: $MachineNameOnly"
    Write-Verbose "  TimeoutSeconds: $TimeoutSeconds"

    $domainPath = Get-DomainPath -DomainName $Domain -Username $Username -Password $Password

    # Extract domain name for authentication
    $domainForAuth = if ($Domain) {
        $Domain
    } else {
        # Extract from domain path
        $dn = $domainPath -replace "LDAP://", ""
        ($dn -split ",DC=" | ForEach-Object { $_ -replace "DC=", "" }) -join "."
    }

    Write-Verbose "Domain path: $domainPath"
    Write-Verbose "Domain for authentication: $domainForAuth"

    # Validate custom credentials if provided
    if ($Username -and $Password) {
        $credentialsValid = Test-Credentials -DomainPath $domainPath -Username $Username -Password $Password
        if (-not $credentialsValid) {
            exit 1
        }
    }

    $computers = Get-Pre2kComputers -DomainPath $domainPath -Username $Username -Password $Password

    if ($computers.Count -eq 0) {
        Write-Host "[*] No pre-Windows 2000 compatible computer accounts found" -ForegroundColor Yellow
        exit 0
    }

    Write-Verbose "Timeout per authentication attempt: $TimeoutSeconds seconds"

    $vulnerableCount = 0
    $totalComputers = $computers.Count

    # Phase 1: Test empty passwords
    if (-not $MachineNameOnly) {
        Write-Host "[*] Phase 1: Testing empty passwords on $totalComputers computer accounts..." -ForegroundColor Cyan
        $progressCounter = 0

        foreach ($computer in $computers) {
            $progressCounter++

            # Update progress every 50 computers or on last computer
            if ($progressCounter % 50 -eq 0 -or $progressCounter -eq $totalComputers) {
                Write-Host "[*] Progress (Empty Password): $progressCounter/$totalComputers" -ForegroundColor Cyan
            }

            $authUsername = "$domainForAuth\$($computer.SAMAccountName)"
            Write-Verbose "Testing computer: $($computer.SAMAccountName) - empty password"

            $emptyPasswordSuccess = Test-Authentication -DomainPath $domainPath -Username $authUsername -Password "" -TimeoutSeconds $TimeoutSeconds

            if ($emptyPasswordSuccess) {
                Write-Host "[!] SUCCESS: $($computer.SAMAccountName) - Empty password" -ForegroundColor Yellow
                $vulnerableCount++
            }
        }
    }

    # Phase 2: Test machine name passwords
    if (-not $EmptyPasswordOnly) {
        Write-Host "[*] Phase 2: Testing machine name passwords on $totalComputers computer accounts..." -ForegroundColor Cyan
        $progressCounter = 0

        foreach ($computer in $computers) {
            $progressCounter++

            # Update progress every 50 computers or on last computer
            if ($progressCounter % 50 -eq 0 -or $progressCounter -eq $totalComputers) {
                Write-Host "[*] Progress (Machine Name Password): $progressCounter/$totalComputers" -ForegroundColor Cyan
            }

            $authUsername = "$domainForAuth\$($computer.SAMAccountName)"
            $machinePassword = Get-MachinePassword -SAMAccountName $computer.SAMAccountName
            Write-Verbose "Testing computer: $($computer.SAMAccountName) - password: $machinePassword"

            $machinePasswordSuccess = Test-Authentication -DomainPath $domainPath -Username $authUsername -Password $machinePassword -TimeoutSeconds $TimeoutSeconds

            if ($machinePasswordSuccess) {
                Write-Host "[!] SUCCESS: $($computer.SAMAccountName) - Password matches machine name" -ForegroundColor Yellow
                $vulnerableCount++
            }
        }
    }

    Write-Host "[+] Scan complete. $vulnerableCount vulnerable accounts found." -ForegroundColor Green

} catch {
    Write-Host "[!] ERROR: An unexpected error occurred: $_" -ForegroundColor Red
    Write-Verbose "Exception details: $($_.Exception | Format-List * -Force | Out-String)"
    exit 1
}
