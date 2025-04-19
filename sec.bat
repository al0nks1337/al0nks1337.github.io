powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-LocalUser -Name '%USERNAME%' -PasswordNeverExpires $false"

powershell -Command "[ADSI]$user='WinNT://./%USERNAME%'; $user.Put('PasswordExpired', 1); $user.SetInfo()"

wmic UserAccount where "Name='%USERNAME%' and Domain='%COMPUTERNAME%'" set PasswordExpires=TRUE
wmic UserAccount where "Name='%USERNAME%' and Domain='%COMPUTERNAME%'" set PasswordExpires=True
wmic UserAccount where Name="%USERNAME%" set PasswordExpires=TRUE
wmic UserAccount where Name="%USERNAME%" set PasswordExpires=True

net user %username% /logonpasswordchg:yes
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-LocalUser -Name '%USERNAME%' -UserMayChangePassword $true"
