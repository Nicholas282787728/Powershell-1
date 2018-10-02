###### Fri Sep 28 10:17:27 AEST 2018 check disconnected mailbox
Get-MailboxDatabase | Get-MailboxStatistics | Where-Object { $_.DisplayName -like "*brani*" } | Format-List DisplayName,Database,DisconnectReason
###### Mon Sep 17 12:27:02 AEST 2018
Get-OfflineAddressBook | Update-OfflineAddressBook
###### Wed Sep 19 12:36:23 AEST 2018 exchange
Get-Mailbox -ResultSize unlimited | Get-MailboxJunkEmailConfiguration | Where-Object {$_.Enabled -eq $False}
###### Tue Sep 25 16:25:18 AEST 2018 exchange quota
Set-Mailbox username@gratex.com.au -Type shared -ProhibitSendReceiveQuota 9.4GB -ProhibitSendQuota 9.2GB -IssueWarningQuota 9GB -UseDatabaseQuotaDefaults $False
