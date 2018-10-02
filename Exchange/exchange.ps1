###### Fri Sep 28 10:17:27 AEST 2018 check disconnected mailbox
Get-MailboxDatabase | Get-MailboxStatistics | Where-Object { $_.DisplayName -like "*brani*" } | Format-List DisplayName,Database,DisconnectReason
###### Mon Sep 17 12:27:02 AEST 2018 update oab
Get-OfflineAddressBook | Update-OfflineAddressBook
###### Wed Sep 19 12:36:23 AEST 2018 exchange
Get-Mailbox -ResultSize unlimited | Get-MailboxJunkEmailConfiguration | Where-Object {$_.Enabled -eq $False}
###### Tue Sep 25 16:25:18 AEST 2018 exchange quota
Set-Mailbox username@gratex.com.au -Type shared -ProhibitSendReceiveQuota 9.4GB -ProhibitSendQuota 9.2GB -IssueWarningQuota 9GB -UseDatabaseQuotaDefaults $False
###### Tue Oct 2 14:06:05 AEST 2018 verify whether protocol logging form ms
Write-Host "Send Connectors:" -ForegroundColor yellow; Get-SendConnector | Format-List Name, ProtocolLoggingLevel; Write-Host "Receive Connectors:" -ForegroundColor yellow; Get-ReceiveConnector | Format-List Name, TransportRole, ProtocolLoggingLevel; Write-Host "Mailbox Transport Delivery service:" -ForegroundColor yellow; Get-MailboxTransportService | Format-List *ProtocolLoggingLevel; Write-Host "Front End Transport service:" -ForegroundColor yellow; Get-FrontEndTransportService | Format-List *ProtocolLoggingLevel; Write-Host "Transport service and Mailbox Transport Submission service:" -ForegroundColor yellow; Get-TransportService | Format-List *ProtocolLoggingLevel
###### Tue Oct 2 14:07:10 AEST 2018 verify logging files
Write-Host "Front End Transport service:" -ForegroundColor yellow; Get-FrontEndTransportService | Format-List ReceiveProtocolLog*, SendProtocolLog*; Write-Host "Mailbox Transport Submission and Mailbox Transport Delivery services:" -ForegroundColor yellow; Get-MailboxTransportService | Format-List ReceiveProtocolLog*, SendProtocolLog*; Write-Host "Transport service:" -ForegroundColor yellow; Get-TransportService | Format-List ReceiveProtocolLog*, SendProtocolLog*
