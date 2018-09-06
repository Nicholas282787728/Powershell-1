$PSVersionTable
get-host

%USERPROFILE%\Documents\WindowsPowerShell\Modules
%WINDIR%\System32\WindowsPowerShell\v1.0\Modules

Get-EventLog  -After (Get-Date).AddDays(-31) system -EntryType Error
Get-ADComputer -Filter * -Properties * | Format-Table Name, LastLogonDate -Autosize

Get-ADUser -Identity 'honeypot' | Select-Object SID
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010;
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;
Get-MessageTrackingLog -ResultSize Unlimited -Start "1/03/2018 8:00AM" -End "1/04/2018 5:00PM" -EventId "Fail" -Recipients "dgm@owenhodge.com.au"
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

###### Thu Sep 6 08:39:02 AEST 2018  system up time

$uptime = Get-WmiObject -Class Win32_OperatingSystem
$uptime
$uptime.ConvertToDateTime($uptime.LocalDateTime) – $uptime.ConvertToDateTime($uptime.LastBootUpTime)

###### Thu Sep 6 10:41:15 AEST 2018 powershell connection

Install-Module -Name Microsoft.Online.SharePoint.PowerShell


###### Thu Sep 6 12:24:22 AEST 2018 batch rename

Get-ChildItem Y:\velosure | `
    Where-Object {$_.name -like "*(4)*"} |`
    #Rename-Item -NewName { $_.Name -replace ' ','_' }
Rename-Item -NewName { $_.Name -replace "\ -\ Copy \(4\)", ""}

###### Thu Sep 6 15:41:12 AEST 2018 select-string
systeminfo | Select-String -Pattern time, date

Get-ADUser user1  | out-string -Stream | Select-String -Pattern "obj"
Get-mailbox payable@company.com -Filter * | Format-List -Property * | out-string -Stream |Select-S
tring -Pattern "@"
