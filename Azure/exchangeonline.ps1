Set-ExecutionPolicy RemoteSigned
$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
Import-PSSession $Session -DisableNameChecking
Remove-PSSession $Session
###### Mon Nov 12 13:24:45 AEDT 2018 setup autoreply endtime
set-ccMailboxAutoReplyConfiguration -Identity johnt  -EndTime
Import-PSSession $exchangeSession -Prefix cc  #important, change time to your local
