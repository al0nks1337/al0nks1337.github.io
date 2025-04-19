powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-LocalUser -Name '%USERNAME%' -PasswordNeverExpires $false"
if errorlevel 1 (
    echo [!] failed to set passwordneverexpires via powershell. trying wmic
    wmic UserAccount where "Name='%USERNAME%' and Domain='%COMPUTERNAME%'" set PasswordExpires=TRUE
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-LocalUser -Name '%USERNAME%' -PasswordNeverExpires $false"
if errorlevel 1 (
    echo [!] failed to set passwordneverexpires via powershell. trying wmic
    wmic UserAccount where "Name='%USERNAME%' and Domain='%COMPUTERNAME%'" set PasswordExpires=TRUE
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-LocalUser -Name '%USERNAME%' -PasswordNeverExpires $false"
if errorlevel 1 (
    echo [!] failed to set passwordneverexpires via powershell. trying wmic
    wmic UserAccount where "Name='%USERNAME%' and Domain='%COMPUTERNAME%'" set PasswordExpires=TRUE
)

powershell -Command "[ADSI]$user='WinNT://./%USERNAME%'; $user.Put('PasswordExpired', 1); $user.SetInfo()"
if errorlevel 1 echo [!] failed to set passwordexpired via adsi
powershell -Command "[ADSI]$user='WinNT://./%USERNAME%'; $user.Put('PasswordExpired', 1); $user.SetInfo()"
if errorlevel 1 echo [!] failed to set passwordexpired via adsi
powershell -Command "[ADSI]$user='WinNT://./%USERNAME%'; $user.Put('PasswordExpired', 1); $user.SetInfo()"
if errorlevel 1 echo [!] failed to set passwordexpired via adsi

net user %username% /logonpasswordchg:yes >nul 2>&1
if errorlevel 1 echo [!] failed to set logonpasswordchg
net user %username% /logonpasswordchg:yes >nul 2>&1
if errorlevel 1 echo [!] failed to set logonpasswordchg
net user %username% /logonpasswordchg:yes >nul 2>&1
if errorlevel 1 echo [!] failed to set logonpasswordchg
