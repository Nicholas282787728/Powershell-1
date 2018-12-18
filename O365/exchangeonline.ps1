Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $Cred -Authentication Basic -AllowRedirection
Import-PSSession $Session -DisableNameChecking
Remove-PSSession $Session
###### Mon Nov 12 13:24:45 AEDT 2018 setup autoreply endtime
set-ccMailboxAutoReplyConfiguration -Identity johnt  -EndTime
Import-PSSession $exchangeSession -Prefix cc  #important, change time to your local
#! convert to shared mailbox and setup quota
Get-Mailbox -identity engineering@domainname.com | set-mailbox -type “Shared”
Set-Mailbox engineering@domainname.com -ProhibitSendReceiveQuota 50GB -ProhibitSendQuota 49.75GB -IssueWarningQuota 49.5GB
#! assign permissions to shared mailbox
Add-MailboxPermission engineering@domainname.com -User "Engineering Group" -AccessRights FullAccess
###### Mon Nov 26 23:29:51 AEDT 2018
Get-Mailbox -Identity wii | Format-List *type*
###### Wed Dec 12 17:17:46 AEDT 2018 reset user default lanuage
set-MailboxRegionalConfiguration -id leim -LocalizeDefaultFolderName:$true -Language sk-SK -DateFormat d/MM/yyyy