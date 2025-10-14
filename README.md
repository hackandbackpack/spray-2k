# PowerShell2k - Pre-Windows 2000 Compatible Computer Account Scanner

A production-ready tool for identifying pre-Windows 2000 compatible computer accounts in Active Directory environments. These accounts are often created with weak or default passwords, representing a significant security risk.

## Overview

PowerShell2k includes two implementations for maximum flexibility:
- **PowerShell Script** (`Invoke-Pre2k.ps1`) - No external modules required
- **C# Binary** (`Pre2k.exe`) - Cobalt Strike execute-assembly compatible

Both implementations query Active Directory for computer accounts with the pre-Windows 2000 compatible flag (`userAccountControl:1.2.840.113556.1.4.803:=4128`) and test for two common weak authentication scenarios:
1. Empty passwords
2. Passwords matching the lowercase machine name (first 14 characters)

## Features

- No external dependencies (PowerShell version uses only built-in ADSI/DirectoryServices)
- Runs in current user context by default
- Optional custom credentials support
- Configurable authentication timeouts (default: 10 seconds)
- Progress tracking for large domains
- Clean, concise output showing only vulnerable accounts
- Production-ready error handling
- Verbose logging for debugging (PowerShell)
- Cobalt Strike compatible (C# version)

## Installation

```powershell
git clone https://github.com/hackandbackpack/powershell2k.git
cd powershell2k
```

No additional installation required. The PowerShell script runs directly, and the C# binary is pre-compiled.

## Usage

### PowerShell Version

#### Basic Usage (Current User Context)
```powershell
.\Invoke-Pre2k.ps1
```

#### Test Only Empty Passwords
```powershell
.\Invoke-Pre2k.ps1 -EmptyPasswordOnly
```

#### Test Only Machine Name Passwords
```powershell
.\Invoke-Pre2k.ps1 -MachineNameOnly
```

#### Target Specific Domain
```powershell
.\Invoke-Pre2k.ps1 -Domain "contoso.com"
```

#### Use Custom Credentials
```powershell
$password = Read-Host -AsSecureString -Prompt "Enter password"
.\Invoke-Pre2k.ps1 -Username "DOMAIN\user" -Password $password
```

#### Custom Timeout
```powershell
.\Invoke-Pre2k.ps1 -TimeoutSeconds 15
```

#### Verbose Mode for Debugging
```powershell
.\Invoke-Pre2k.ps1 -Verbose
```

### C# Version

#### Basic Usage (Current User Context)
```powershell
.\Pre2k.exe
```

#### Test Only Empty Passwords
```powershell
.\Pre2k.exe /emptyonly
```

#### Test Only Machine Name Passwords
```powershell
.\Pre2k.exe /nameonly
```

#### Target Specific Domain
```powershell
.\Pre2k.exe /domain:contoso.com
```

#### Use Custom Credentials
```powershell
.\Pre2k.exe /username:DOMAIN\user /password:Password123
```

#### Custom Timeout
```powershell
.\Pre2k.exe /timeout:15
```

#### Help
```powershell
.\Pre2k.exe /help
```

### Cobalt Strike Usage

```
execute-assembly C:\path\to\Pre2k.exe
execute-assembly C:\path\to\Pre2k.exe /emptyonly
execute-assembly C:\path\to\Pre2k.exe /domain:contoso.com
```

## Output Examples

```
[*] Querying domain for computer accounts...
[+] Found 1523 computer accounts
[*] Testing authentication...
[*] Progress: 50/1523
[*] Progress: 100/1523
[!] SUCCESS: DC01$ - Empty password
[*] Progress: 150/1523
[!] SUCCESS: LEGACY-SRV$ - Password matches machine name
[*] Progress: 200/1523
...
[+] Scan complete. 2 vulnerable accounts found.
```

## Parameters

### PowerShell

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-EmptyPasswordOnly` | Switch | No | Only test empty passwords |
| `-MachineNameOnly` | Switch | No | Only test machine name passwords |
| `-Username` | String | No | Custom username (must be paired with Password) |
| `-Password` | SecureString | No | Custom password (must be paired with Username) |
| `-Domain` | String | No | Target domain (default: current domain) |
| `-TimeoutSeconds` | Int | No | Authentication timeout in seconds (default: 10) |
| `-Verbose` | Switch | No | Enable verbose logging |

### C# Binary

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `/emptyonly` | Flag | No | Only test empty passwords |
| `/nameonly` | Flag | No | Only test machine name passwords |
| `/username:<user>` | String | No | Custom username (must be paired with password) |
| `/password:<pass>` | String | No | Custom password (must be paired with username) |
| `/domain:<domain>` | String | No | Target domain (default: current domain) |
| `/timeout:<seconds>` | Int | No | Authentication timeout in seconds (default: 10) |
| `/help` or `/?` | Flag | No | Show help message |

## Requirements

### PowerShell Version
- PowerShell 3.0 or later
- Network access to Active Directory
- Sufficient permissions to query computer objects (typically Domain Users)
- Domain-joined machine or network connectivity to domain controllers

### C# Version
- .NET Framework 4.0 or later
- Network access to Active Directory
- Sufficient permissions to query computer objects (typically Domain Users)
- Can run from non-domain-joined machines with proper credentials

## Technical Details

### Vulnerability Background

Pre-Windows 2000 compatible computer accounts are created when the "Assign this computer account as a pre-Windows 2000 computer" option is selected during computer creation or when older deployment methods are used. These accounts have:

- `userAccountControl` attribute value of **4128** (PASSWD_NOTREQD=32 + WORKSTATION_TRUST_ACCOUNT=4096)
- Default password set to the **lowercase machine name** (without `$` suffix, limited to first 14 characters)
- Example: `WORKSTATION01$` has default password `workstation01`

Accounts that were pre-created but never joined to the domain retain this weak password indefinitely, allowing unauthorized authentication.

### LDAP Query

Both implementations use this LDAP filter:
```
(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=4128))
```

This uses the bitwise AND matching rule (`1.2.840.113556.1.4.803`) to efficiently find accounts with the pre-Windows 2000 flag.

### Authentication Testing

Both implementations test authentication using LDAP Simple Bind via DirectoryEntry with:
- **Format**: `DOMAIN\COMPUTERNAME$`
- **Passwords**: Empty string (`""`) and lowercase machine name
- **Timeout**: Configurable (default 10 seconds) to prevent hanging
- **Error Handling**: Silently handles expected authentication failures, only reports successes

### Performance

- Uses paged searches (`PageSize = 1000`) for efficient queries in large domains
- Only retrieves necessary attributes (`sAMAccountName`, `dNSHostName`, `userAccountControl`)
- Progress updates every 50 computers to minimize output noise
- Timeout prevents hanging on unreachable domain controllers

## Compilation (C# Version)

To recompile the C# version:

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:exe /out:Pre2k.exe Pre2k.cs
```

Or using PowerShell:

```powershell
Add-Type -Path .\Pre2k.cs -OutputAssembly .\Pre2k.exe -OutputType ConsoleApplication
```

## Security Considerations

This tool is designed for:
- **Security assessments** by authorized personnel
- **Penetration testing** with proper authorization
- **Red team operations** with appropriate scope
- **Security audits** to identify weak configurations

### Defensive Use

Defenders can use this tool to:
1. Identify pre-Windows 2000 compatible accounts in their environment
2. Remediate by resetting passwords or disabling accounts
3. Monitor for creation of new vulnerable accounts
4. Validate remediation efforts

### Remediation

To fix identified vulnerabilities:

```powershell
# Reset computer account password
Reset-ComputerMachinePassword -Server DC01

# Or disable unused accounts
Disable-ADAccount -Identity "COMPUTERNAME$"

# Or remove pre-Windows 2000 flag
Set-ADComputer -Identity "COMPUTERNAME$" -Replace @{userAccountControl=4096}
```

## Detection

Defenders should monitor for:
- Multiple LDAP queries with the bitwise filter for `userAccountControl:1.2.840.113556.1.4.803:=4128`
- Repeated authentication attempts against multiple computer accounts
- Authentication from unusual sources using computer account credentials
- Failed authentication attempts against computer accounts (may indicate scanning)

## Troubleshooting

### "Failed to query domain"
- Verify network connectivity to domain controller
- Ensure current user has permissions to query AD
- Check domain name is correct (if specified)
- Try running with `-Verbose` flag to see detailed errors

### "Failed to validate custom credentials"
- Verify username format (should be `DOMAIN\username`)
- Ensure password is correct
- Check user has permissions to access AD
- Verify domain name is correct

### Slow Performance
- Increase `-TimeoutSeconds` for slow networks
- Ensure domain controllers are responsive
- Check network bandwidth and latency
- Consider targeting specific OUs (requires code modification)

### No Vulnerable Accounts Found
- This is good! It means no pre-Windows 2000 accounts have weak passwords
- Verify the query is finding accounts with `-Verbose` flag
- Check that accounts haven't been remediated

## Credits

Inspired by the original [pre2k](https://github.com/garrettfoster13/pre2k) tool by @unsigned_sh0rt and @Tw1sm.

Research and methodology based on work from:
- TrustedSec
- Optiv
- Various security researchers in the Active Directory security community

## License

This tool is provided for authorized security testing and assessment purposes only. Users are responsible for ensuring they have proper authorization before running this tool against any systems.

## Disclaimer

This tool is provided "as is" without warranty of any kind. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before performing security assessments.
