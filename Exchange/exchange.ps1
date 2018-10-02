###### Fri Sep 28 10:17:27 AEST 2018 check disconnected mailbox
Get-MailboxDatabase | Get-MailboxStatistics | Where-Object { $_.DisplayName -like "*brani*" } | Format-List DisplayName,Database,DisconnectReason
###### Mon Sep 17 12:27:02 AEST 2018
Get-OfflineAddressBook | Update-OfflineAddressBook
