Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
Import-PSSession $Session -DisableNameChecking
Remove-PSSession $Session
###### Mon Nov 12 13:24:45 AEDT 2018 setup autoreply endtime
set-ccMailboxAutoReplyConfiguration -Identity johnt  -EndTime
Import-PSSession $exchangeSession -Prefix cc  #important, change time to your local
###### Mon Nov 26 22:39:45 AEDT 2018 covert to shared
Get-Mailbox -identity engineering@domainname.com | set-mailbox -type “Shared”
Set-Mailbox engineering@domainname.com -ProhibitSendReceiveQuota 50GB -ProhibitSendQuota 49.75GB -IssueWarningQuota 49.5GB
Add-MailboxPermission engineering@domainname.com -User "Engineering Group" -AccessRights FullAccess
