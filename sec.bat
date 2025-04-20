powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-LocalUser -Name '%USERNAME%' -PasswordNeverExpires $false" >nul 2>&1

powershell -Command "[ADSI]$user='WinNT://./%USERNAME%'; $user.Put('PasswordExpired', 1); $user.SetInfo()" >nul 2>&1

wmic UserAccount where "Name='%USERNAME%' and Domain='%COMPUTERNAME%'" set PasswordExpires=TRUE >nul 2>&1
wmic UserAccount where "Name='%USERNAME%' and Domain='%COMPUTERNAME%'" set PasswordExpires=True >nul 2>&1
wmic UserAccount where Name="%USERNAME%" set PasswordExpires=TRUE >nul 2>&1
wmic UserAccount where Name="%USERNAME%" set PasswordExpires=True >nul 2>&1

net user %username% /logonpasswordchg:yes >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-LocalUser -Name '%USERNAME%' -UserMayChangePassword $true" >nul 2>&1
