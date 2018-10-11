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
###### Tue Sep 11 15:25:03 AEST 2018 powershell exchange defaul shortcut command
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noexit -command ". 'C:\Program Files\Microsoft\Exchange Server\V15\bin\RemoteExchange.ps1'; Connect-ExchangeServer -auto -ClientApplication:ManagementShell "
###### Tue Sep 11 15:32:38 AEST 2018 exchange count mailbox created by year
Get-Mailbox *store  | Select-Object alias, UserPrincipalName, whencreated, RecipientType, RecipientTypedetails |  Sort-Object whencreated -Descending | Group-Object {$_.whencreated.date.year} -NoElement
###### Thu Oct 11 11:10:48 AEDT 2018 General snapin
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010;
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;
Get-MessageTrackingLog -ResultSize Unlimited -Start ((Get-Date).AddMinutes(-10)) -EventId "Fail" -Recipients "dgm@owenhodge.com.au" -sender
Get-MailboxJunkEmailConfiguration -Identity dgm@abc.com.au -ResultSize unlimited | out-file c:\temp\list.txt -Width 1000
Get-MailboxJunkEmailConfiguration -Identity dgm@abc.com.au -TrustedSendersAndDomains @{Add = "ato.gov.au", "INDAdvice@ato.gov.au", "noreply@ato.gov.au"}
Set-MailboxSentItemsConfiguration "Mailbox Name" -SendAsItemsCopiedTo SenderAndFrom -SendOnBehalfOfItemsCopiedTo SenderAndFrom
Get-Mailbox -RecipientTypeDetails SharedMailbox | Set-Mailbox -MessageCopyForSentAsEnabled $true -MessageCopyForSendOnBehalfEnabled $true
Get-MailboxStatistics [username] | Format-Table DisplayName, TotalItemSize, ItemCount
###### Thu Oct 11 11:09:02 AEDT 2018 check database white space
Get-Mailbox | Group-Object -Property:Database | Select-Object Name, Count | Sort-Object Name | Format-Table -Auto
Get-Mailbox -resultsize:unlimited | group-object -property:database | sort-object
Get-MailBoxDatabase -status | Format-Table Name, DatabaseSize, AvailableNewMailboxSpace -auto
Get-MailboxDatabaseCopyStatus | Select-Object ContentIndexState, ContentIndexErrorMessage | Format-List
Set-MailboxDatabase "Database Name" -IndexEnabled $False