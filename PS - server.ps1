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
Get-ADComputer -Filter * -Properties * | Format-Table Name, LastLogonDate -Autosize
Get-ADUser -Identity 'honeypot' | Select-Object SID
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010;
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;
Get-MessageTrackingLog -ResultSize Unlimited -Start ((Get-Date).AddMinutes(-10)) -EventId "Fail" -Recipients "dgm@owenhodge.com.au" -sender
Get-MailboxJunkEmailConfiguration -Identity dgm@abc.com.au -ResultSize unlimited | out-file c:\t
emp\list.txt -Width 1000
Get-MailboxJunkEmailConfiguration -Identity dgm@abc.com.au -TrustedSendersAndDomains @{Add = "ato.gov.au", "INDAdvice@ato.gov.au", "noreply@ato.gov.au"}
office2010
Set-MailboxSentItemsConfiguration "Mailbox Name" -SendAsItemsCopiedTo SenderAndFrom -SendOnBehalfOfItemsCopiedTo SenderAndFrom
office2013them
Get-Mailbox -RecipientTypeDetails SharedMailbox | Set-Mailbox -MessageCopyForSentAsEnabled $true -MessageCopyForSendOnBehalfEnabled $true
Get-MailboxStatistics [username] | Format-Table DisplayName, TotalItemSize, ItemCount
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
Get-ADUser -Identity dlltransfer -Properties whenCreated
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
Get-ADComputer -Filter * -Properties * | Select-Object -Property name, OperatingSystem, LastLogonDate |Where-Object {$_.Operatingsystem -like "*8.1*"} |Sort-Object -Property OperatingSystem, LastLogonDate | Format-Table -AutoSize
Get-ChildItem env:*
$env:username
Get-CimInstance Win32_OperatingSystem | Format-List *
Set-ADAccountExpiration -DateTime "1/8/2018 6:30 PM" -Identity pxb
Get-ADuser -Identity pxb -Properties * | more
Set-ExecutionPolicy remoteSigned
#########################################################################################
lsblk
sudo resize2fs /dev/mapper/vg--Backup-lv--Backup
#########################################################################################
Get-Mailbox | Group-Object -Property:Database | Select-Object Name, Count | Sort-Object Name | Format-Table -Auto
Get-Mailbox -resultsize:unlimited | group-object -property:database | sort-object
Get-MailBoxDatabase -status | Format-Table Name, DatabaseSize, AvailableNewMailboxSpace -auto
Get-MailboxDatabaseCopyStatus | Select-Object ContentIndexState, ContentIndexErrorMessage | Format-List
Set-MailboxDatabase "Database Name" -IndexEnabled $False
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
Get-ADUser user1  | out-string -Stream | Select-String -Pattern "obj"
Get-mailbox payable@company.com -Filter * | Format-List -Property * | out-string -Stream | Select-String -Pattern "@"
###### Fri Sep 7 10:47:08 AEST 2018 move computer to OU
Get-ADComputer -Filter 'Name -like "ahleap*"'
$target = Get-ADOrganizationalUnit -LDAPFilter "(name=charlotte)"
get-adcomputer win7-c1 | Move-ADObject -TargetPath $target.DistinguishedName
###### Fri Sep 7 10:47:15 AEST 2018  remote session
$cred = Get-Credential -UserName "domain\username" -Message " " ; new-pssession -ComputerName computer -Credential $cred
###### Fri Sep 7 11:01:55 AEST 2018 AD user operation
Get-aduser -filter "department -eq 'marketing' -AND enabled -eq 'True'"
Set-ADAccountPassword jfrost -NewPassword $newpwd -Reset -PassThru | Set-ADuser -ChangePasswordAtLogon $True | Unlock-ADAccount
Enable-ADAccount -Identity test

get-aduser richarda -Properties * | Select-Object *lock*
Set-ADAccountPassword richarda -Reset -PassThru | Set-ADuser -ChangePasswordAtLogon $True | Unlock-ADAccount
###### Fri Sep 7 14:37:57 AEST 2018  get ad group creation date
$GroupList = Get-ADGroup -Filter * -Properties Name, DistinguishedName, GroupCategory, GroupScope, whenCreated, WhenChanged, member, memberOf, sIDHistory, SamAccountName, Description, AdminCount | Select-Object Name, DistinguishedName, GroupCategory, GroupScope, whenCreated, whenChanged, member, memberOf, AdminCount, SamAccountName, Description, `
@{name = 'MemberCount'; expression = {$_.member.count}}, `
@{name = 'MemberOfCount'; expression = {$_.memberOf.count}}, `
@{name = 'SIDHistory'; expression = {$_.sIDHistory -join ','}}, `
@{name = 'DaysSinceChange'; expression = {[math]::Round((New-TimeSpan $_.whenChanged).TotalDays, 0)}} | Sort-Object Name
$GroupList | Select-Object Name, GroupCategory, GroupScope, whenCreated, whenChanged, DaysSinceChange, MemberCount, MemberOfCount, AdminCount, Description, DistinguishedName
Get-ADGroup -Filter * -Properties * | Select-Object -Property name, whencreated, DistinguishedName | Sort-Object whencreated | Out-GridView
New-ADGroup -Name "dwgtrueview" -SamAccountName dwgtrueview -GroupCategory Security -GroupScope Global -Path "OU=Security Groups,OU=MyBusiness,DC=domain,DC=local"
###### Mon Sep 10 11:06:13 AEST 2018  quser and logoff
$userName = 'administrator'
$sessionId = ((quser /server:DC | Where-Object { $_ -match $userName }) -split ' +')[2]
$sessionid
###### Sat Sep 8 12:56:14 AEST 2018  windows features
Get-WindowsFeature updateservices*
Install-WindowsFeature updateservices -IncludeManagementTools
Get-Command -Module updateservices
Install-WindowsFeature -Name UpdateServices, UpdateServices-DB -IncludeManagementTools
Get-Command -Module neteventpackagecapture

###### Tue Sep 11 14:25:30 AEST 2018 event logs
Get-WinEvent -ComputerName . -FilterHashtable @{LogName = "Security"; ID = 4634} -MaxEvents 200000  | Select-Object -First 5 | Where-Object {$_.message -like "*LEI_laptop*"}
###### Tue Sep 11 15:25:03 AEST 2018 powershell exchange defaul shortcut command
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noexit -command ". 'C:\Program Files\Microsoft\Exchange Server\V15\bin\RemoteExchange.ps1'; Connect-ExchangeServer -auto -ClientApplication:ManagementShell "
###### Tue Sep 11 15:32:38 AEST 2018 exchange count mailbox created by year
Get-Mailbox *store  | Select-Object alias, UserPrincipalName, whencreated, RecipientType, RecipientTypedetails |  Sort-Object whencreated -Descending | Group-Object {$_.whencreated.date.year} -NoElement

###### Fri Sep 14 10:13:09 AEST 2018 rename pbk
powershell -Command "(gc C:\ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk) -replace '[Old name]', '[New name]' | Out-File C:\ProgramData\Microsoft\Network\Connections\Pbk\rasphone.pbk"
taskkill /im "explorer.exe" /f
Start-Process "" "explorer.exe"
###### Fri Sep 14 13:58:31 AEST 2018 ad sync
Import-Module ADSync
Start-ADSyncSyncCycle -PolicyType Delta
Start-ADSyncSyncCycle -PolicyType Initial
###### Fri Sep 14 14:17:07 AEST 2018 o365 powershell###### Mon Sep 17 08:45:16 AEST 2018
Install-Module -Name AzureAD
Connect-AzureAD
Connect-MsolService

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

###### Mon Sep 17 12:27:02 AEST 2018
Get-OfflineAddressBook | Update-OfflineAddressBook
###### Mon Sep 17 21:40:07 AEST 2018 credentialmanager
Install-Module -Name "CredentialManager"

$Target = "server"
$UserName = "domain\user"
$Secure = Read-host -AsSecureString
New-StoredCredential -Target $Target -UserName $UserName -SecurePassword $Secure -Persist LocalMachine -Type Generic

