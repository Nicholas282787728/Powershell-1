lsrfqhkcvdgdrnkd azuread app pass GRA skype
rsyjwpbpddfhxjxq o
zmnqcpwdtfygglfg opopup

$PSVersionTable
get-host
###### Fri Sep 7 11:24:37 AEST 2018 powershell profile
#Clear-Host
#Start-Process powershell -Verb runAs
# Welcome message
$time = Get-Date -Format g
$host.ui.RawUI.WindowTitle += " - " + $env:COMPUTERNAME + " - " + $env:Username + " - " + $time
Get-ChildItem c:\temp -Filter *.txt | Where-Object {$_.Length -lt 1000} | Remove-Item
Start-Transcript -OutputDirectory c:\temp
###### Fri Sep 7 11:25:26 AEST 2018
%USERPROFILE%\Documents\WindowsPowerShell\Modules
%WINDIR%\System32\WindowsPowerShell\v1.0\Modules
Get-EventLog  -After (Get-Date).AddDays(-31) system -EntryType Error
###### Mon Aug 27 17:38:13 AEST 2018
Import-Module ADSync
Start-ADSyncSyncCycle -PolicyType Delta
Enable-PSRemoting -Force
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
Import-Module powershellget
Install-Module -Name AzureAD -Scope CurrentUser
$UserCredential = Get-Credential
Connect-AzureAD -Credential $UserCredential
disconnect-AzureAD
Enter-PSSession -ComputerName COMPUTER -Credential USER
Add-MailboxFolderPermission -identity “Managingdirector:\Calendar” -user “personalassistant” -AccessRights editor
Get-ChildItem -r * | Where-Object {$_.FullName.Length -gt 220} | Select-Object fullname |Export-Csv  c:\temp\filepathgt220.csv
$ScriptFiles = Get-ChildItem D:\* -Include *.ps1 -Recurse | Where-Object {$_.creationtime -gt "01/01/2011"}
$ScriptFiles = $ScriptFiles | Select-Object -Property Name, CreationTime, LastWriteTime, IsReadOnly
$ScriptFiles | Export-Csv -Append -Path "\\Archive01\Scripts\Scripts.csv"
Start-Process -Credential "company\user" powershell
Enter-PSSession -ComputerName abc
Start-Process powershell -Verb runAs
Import-Module ActiveDirectory
Get-ChildItem env:*
$env:username
Get-CimInstance Win32_OperatingSystem | Format-List *
Set-ExecutionPolicy remoteSigned
#########################################################################################
lsblk
sudo resize2fs /dev/mapper/vg--Backup-lv--Backup
#########################################################################################
shell:startup
shell:common startup
#remoting powershell via web
Install-Windowsfeature WindowsPowerShellWebaccess -IncludeManagementTools
Install-PswaWebApplication -UseTestCertificate
Add-PswaAuthorizationRule -UserName * -ComputerName * -ConfigurationName *
#batch user creating
1..10 | Foreach-Object {New-ADUser -Name Student$_ -AccountPassword (ConvertTo-SecureString "Pa$$w000rd" -AsPlainText -Force) -UserPrincipalName Student$_@$env:userdnsdomain -ChangePasswordAtLogon 1 -Enabled 1 -Verbose}
# show folder size
"{0:N2} MB" -f ((Get-ChildItem -Recurse | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB)
# folder size module
Install-Module PSFolderSize
Get-FolderSize c:\users\user
###### Wed Sep 5 11:17:33 AEST 2018  #? powershell startup scipt
$time = Get-Date -Format g
$host.ui.RawUI.WindowTitle += " - " + $env:COMPUTERNAME + " - " + $env:Username + " - " + $time
###### Wed Sep 5 11:17:08 AEST 2018  #? system up time
$uptime = Get-WmiObject -Class Win32_OperatingSystem
$uptime
$uptime.ConvertToDateTime($uptime.LocalDateTime) – $uptime.ConvertToDateTime($uptime.LastBootUpTime)
###### Thu Sep 6 10:41:15 AEST 2018 powershell connection
Install-Module -Name Microsoft.Online.SharePoint.PowerShell
###### Thu Sep 6 12:24:22 AEST 2018 folder batch rename
Get-ChildItem Y:\velosure | `
    Where-Object {$_.name -like "*(4)*"} |`
    #Rename-Item -NewName { $_.Name -replace ' ','_' }
Rename-Item -NewName { $_.Name -replace "\ -\ Copy \(4\)", ""}
###### Thu Sep 6 15:41:12 AEST 2018 select-string
systeminfo | Select-String -Pattern time, date
Get-mailbox payable@company.com -Filter * | Format-List -Property * | out-string -Stream | Select-String -Pattern "@"
###### Fri Sep 7 10:47:15 AEST 2018  remote session
$cred = Get-Credential -UserName "domain\username" -Message " " ; new-pssession -ComputerName computer -Credential $cred
###### Sat Sep 8 12:56:14 AEST 2018  windows features
Get-WindowsFeature updateservices*
Install-WindowsFeature updateservices -IncludeManagementTools
Get-Command -Module updateservices
Install-WindowsFeature -Name UpdateServices, UpdateServices-DB -IncludeManagementTools
Get-Command -Module neteventpackagecapture
###### Tue Sep 11 14:25:30 AEST 2018 event logs
Get-WinEvent -ComputerName . -FilterHashtable @{LogName = "Security"; ID = 4634} -MaxEvents 200000  | Select-Object -First 5 | Where-Object {$_.message -like "*LEI_laptop*"}
###### Fri Sep 14 10:13:09 AEST 2018 rename pbk
powershell -Command "(gc C:\ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk) -replace '[Old name]', '[New name]' | Out-File C:\ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk"
taskkill /im "explorer.exe" /f
Start-Process "" "explorer.exe"
###### Sat Sep 15 09:42:13 AEST 2018   dns powershell
Add-DnsServerForwarder 8.8.8.8
Add-DnsServerConditionalForwarderZone abc.com 8.8.4.4
ipconfig /displydns
Show-DnsServerCache
###### Mon Sep 17 19:42:13 AEST 2018 check disk space
get-wmiobject Win32_LogicalDisk -ComputerName $servers -Filter "DriveType=3"  | `
    Select-Object systemname, Name, volumename, FileSystem, FreeSpace, BlockSize, Size | `
    ForEach-Object {$_.BlockSize = (($_.FreeSpace) / ($_.Size)) * 100; $_.FreeSpace = ($_.FreeSpace / 1GB); $_.Size = ($_.Size / 1GB); $_} | `
    Format-Table systemname, Name, volumename, @{n = 'FS'; e = {$_.FileSystem}}, @{n = 'Free(Gb)'; e = {'{0:N2}' -f $_.FreeSpace}}, @{n = '%Free'; e = {'{0:N2}' -f $_.BlockSize}}, @{n = 'Capacity(Gb)'; e = {'{0:N2}' -f $_.Size}} -AutoSize
###### Mon Sep 17 21:40:07 AEST 2018 credentialmanager
Install-Module -Name "CredentialManager"
$Target = "server"
$UserName = "domain\user"
$Secure = Read-host -AsSecureString
New-StoredCredential -Target $Target -UserName $UserName -SecurePassword $Secure -Persist LocalMachine -Type Generic
Format-Table -Wrap -AutoSize
Select-Object -ExpandProperty
get-process | Format-Table -Property id,Name, @{n='VM(MB)' ;e={$_.VM /1mb} ; formatstring= 'N2'}, @{n='PM(MB)' ;e={$_.PM /1mb} ; formatstring= 'N2'}, @{n='WS(MB)' ;e={$_.WS /1mb} ; formatstring= 'N2'}
Get-History | Select-Object -Property Id, CommandLine, @{n='time'; e={$_.endexecutiontime - $_.startexecutiontime}}
###### Thu Sep 20 09:38:51 AEST 2018 history
C:\Users\user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
Install-Module PSReadLine  # very useful
###### Fri Sep 21 17:02:05 AEST 2018 uninstall software
Get-Package -ProviderName Programs -ov pkgs -name *stardock*| Sort-Object Name,Version | Select-Object Name,@{l="UninstallString";e={$_.Meta.Attributes["UninstallString"]}}
$UninstallCommand = (Get-Package -Name "*Stardock*").Meta.Attributes['UninstallString']
Start-Process -FilePath cmd.exe -ArgumentList '/c', $UninstallCommand -Wait
###### Sat Sep 22 08:41:01 AEST 2018 get-install gackage from mulitple servers
$servers = "dc01", "dc02"
$servers
foreach ($server in $servers) {
    Invoke-Command -ComputerName $server -ScriptBlock {get-package } | Select-Object name, @{n = "server" ; e = {$server}} | Format-Table -GroupBy server -Wrap
}
#or
$servers = "dc01", "dc02"
    Invoke-Command -ComputerName $servers -ScriptBlock {get-package } | Select-Object name, pscomputername | Format-Table -GroupBy pscomputername -Wrap
###### Sun Sep 30 21:49:24 AEST 2018 dns
Set-DnsServerRecursion -ComputerName . -EnableRecursion $false
Add-DnsServerRecursionScope -Name "OurPeople" -EnableRecursion $true
Add-DnsServerQueryResolutionPolicy -Name "OurRecursionPolicy" -Action ALLOW -ApplyOnRecursion -RecursionScope "OurPeople" -ServerInterfaceIP "EQ,192.168.0.12"
Get-DnsServerCache
Set-DnsServerCache -LockingPercent 90
dnscmd /info socketpoolsize
dnscmd /config /socketpoolsize 6783
Get-DnsServerDnsSecZoneSetting -ZoneName test.com
Get-DnsServerTrustAnchor -Name test.com
Get-DnsServerTrustPoint -Name test.com
Get-DnsClientNrptPolicy
Resolve-DnsName abc.com -DnssecOk
Get-DnsServerResponseRateLimiting
Add-DnsServerPrimaryZone -Name "loadbalance.com" -ReplicationScope Domain
Add-DnsServerZoneScope -ZoneName "loadbalance.com" -Name "scope-heavy"
Add-DnsServerZoneScope -ZoneName "loadbalance.com" -Name "scope-light"
Add-DnsServerResourceRecord -ZoneName "loadbalance.com" -A -Name "lb-www" -IPv4Address "192.168.1.11"
Add-DnsServerResourceRecord -ZoneName "loadbalance.com" -A -Name "lb-www" -IPv4Address "192.168.1.22" -ZoneScope "scope-light"
Add-DnsServerResourceRecord -ZoneName "loadbalance.com" -A -Name "lb-www" -IPv4Address "192.168.1.33" -ZoneScope "scope-heavy"
Add-DnsServerQueryResolutionPolicy -Name "our-lb-policy" -Action ALLOW -Fqdn "EQ,*" -ZoneScope "loadbalance.com,1;scope-light,1;scope-heavy,9" -ZoneName "loadbalance.com"
Get-DnsServerQueryResolutionPolicy -ZoneName "loadbalance.com"
Get-DnsServer
###### Mon Oct 1 14:03:55 AEST 2018 dns policy client source address
Get-Command -Module dnsserver -Name *policy*
Add-DnsServerPrimaryZone -Name hmm.com -ReplicationScope Domain
Add-DnsServerClientSubnet -Name 64_subnet -IPv4Subnet "192.168.1.64/26"
Add-DnsServerClientSubnet -Name 128_subnet -IPv4Subnet "192.168.1.128/26"
Add-DnsServerZoneScope -ZoneName hmm.com -Name "64_scope"
Add-DnsServerZoneScope -ZoneName hmm.com -Name "128_scope"
Add-DnsServerResourceRecord -ZoneName hmm.com -A -Name srv-xyz -IPv4Address "22.22.22.22" -ZoneScope "64_scope"
Add-DnsServerResourceRecord -ZoneName hmm.com -A -Name srv-xyz -IPv4Address "33.33.33.33" -ZoneScope "128_scope"
Add-DnsServerQueryResolutionPolicy -Name "64_policy" -Action ALLOW -ClientSubnet "eq,64_subnet" -ZoneScope "64_scop,1" -ZoneName hmm.com
Add-DnsServerQueryResolutionPolicy -Name "128_policy" -Action ALLOW -ClientSubnet "eq,128_subnet" -ZoneScope "128_scop,1" -ZoneName hmm.com
###### Mon Oct 1 14:11:36 AEST 2018 change ip address command
Get-NetIPAddress -InterfaceIndex 1 -AddressFamily IPv4
netsh interface ipv4 set address name="Ethernet 1" static 192.168.1.129 255.255.255.0 192.168.1.1
###### Mon Oct 1 14:13:57 AEST 2018 dns policy time of day
Get-Date -DisplayHint Time
Get-DnsServerQueryResolutionPolicy -ZoneName hmm.com
Get-DnsServerQueryResolutionPolicy -ZoneName hmm.com -Name "time-policy" -Action deny -timeofday "eq,04:00-23:00" -processingorder 2
###### Tue Oct 2 09:14:01 AEST 2018
(Get-WmiObject win32_bios).serialnumber
###### Thu Oct 4 16:29:39 AEST 2018 last boot time
Get-CimInstance -ClassName win32_operatingsystem | Select-Object csname, lastbootuptime
Get-WmiObject win32_operatingsystem | Select-Object csname, @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}
###### Thu Oct 4 18:38:23 AEST 2018 enable hyper-v
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
###### Thu Oct 4 21:55:09 AEST 2018 winrm version
(Get-Item C:\Windows\System32\wsmsvc.dll).VersionInfo.FileVersion
Test-WSMan -Authentication default
###### Thu Oct 4 22:03:41 AEST 2018 wmi
Get-WmiObject win32_service -ComputerName a,b -Filter "name='bits'" | Invoke-WmiMethod -Name startservice
Get-WmiObject -Class win32_service -ComputerName a -Filter "name='bits'" | ForEach-Object {$_.change($null,$null,$null,$null,$null,$null,$null,'Password')}
Get-CimInstance -ClassName win32_service -Filter "name='bits'" -ComputerName a | Invoke-CimMethod -MethodName Change -Arguments @{startpassword='password'}
Get-WmiObject -Class Win32_LogicalDisk -Filter "drivetype='3'"
$disk=Get-WmiObject -Class Win32_LogicalDisk -Filter "deviceid='c:'"
$disk.volumename = 'system'
$disk.put()
###### Thu Oct 4 22:18:50 AEST 2018 cimsession
$wsman=New-CimSession -ComputerName c,d
$dcom=New-CimSession -ComputerName a,b -SessionOption (New-CimSessionOption -Protocol Dcom)
Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $wsman,$dcom | Select-Object pscomputername,Version,BuildNumber,ServicePackMajorVersion,OSArchitecture | Format-Table
Get-CimSession | Remove-CimSession
###### Thu Oct 4 22:42:58 AEST 2018 cim backup logs
Get-WmiObject -ComputerName localhost -Class win32_nteventlogfile -EnableAllPrivileges -Filter "logfilename='application'" | Invoke-WmiMethod -Name backupeventlog -ArgumentList c:\temp\backup.evt
###### Thu Oct 4 22:53:34 AEST 2018 job locally
Start-Job -ScriptBlock {Get-ChildItem c:\ -Recurse} -Name jobname
Get-Job
Stop-Job -id 1
Receive-Job -Id 1 -Keep
Get-Job | Remove-Job
###### Thu Oct 4 23:02:25 AEST 2018 job remoting
Invoke-Command -ScriptBlock {Get-EventLog -LogName Security -Newest 100} -ComputerName a,b -AsJob -JobName eventloggetter
###### Thu Oct 4 23:04:28 AEST 2018 job wmi
Get-WmiObject -Class Win32_LogicalDisk -ComputerName a,b -AsJob
Get-Job -Id 1 | Select-Object -ExcludeProperty childjobs
Get-Job -id 1 -IncludeChildJob
Get-Job -Id 1 -ChildJobState Completed
Receive-Job -Id 1 | Export-Csv eventlog.csv
Import-Csv .\eventlog.csv | Format-Table -GroupBy pscomputername
###### Thu Oct 4 23:17:51 AEST 2018 cpu usage
(Get-WmiObject win32_processor).loadpercentage
Get-Counter '\Processor(*)\% Processor Time' -Continuous |
    Select-Object -expand CounterSamples |
    Where-Object {$_.InstanceName -eq '_total'}

Get-Counter '\Processor(*)\% Processor Time' -Continuous |
    Select-Object -expand CounterSamples |
    Where-Object{$_.InstanceName -eq '_total' -and $_.CookedValue -gt 40} |
    ForEach-Object{Write-Host $_.CookedValue -fore Red}

###### Fri Oct 5 20:59:55 AEST 2018 last command to clip
(Get-History -Count 1).CommandLine | Set-Clipboard
(Get-History -Count 1).CommandLine | clip
###### Fri Oct 5 22:04:36 AEST 2018 read text file
foreach($line in [System.IO.File]::ReadLines("C:\temp\file.txt"))
{
       new-item -type file -path    c:\temp\test\$line
}

###### Fri Oct 12 10:45:38 AEDT 2018 new user
$username = read-host "Username"
$Password = Read-Host "Password"-AsSecureString

New-LocalUser $UserName -Password $Password -FullName "Third User" -Description "" -AccountNeverExpires -PasswordNeverExpires
Add-LocalGroupMember -Group "administrators" -Member $UserName
###### Fri Oct 12 11:01:04 AEDT 2018 disable logon
Disable-LocalUser
Enable-LocalUser
###### Fri Oct 12 10:58:12 AEDT 2018 reset password
$Password = Read-Host -AsSecureString
$UserAccount = Get-LocalUser -Name "User02"
$UserAccount | Set-LocalUser -Password $Password
###### Tue Oct 16 12:40:36 AEDT 2018 dnsclient check server  address
 Get-DnsClientServerAddress -InterfaceAlias eth* -AddressFamily ipv4 | where {$_.ServerAddresses}
 