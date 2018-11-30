###### Fri Sep 28 10:17:27 AEST 2018 check disconnected mailbox
Get-MailboxDatabase | Get-MailboxStatistics | Where-Object { $_.DisplayName -like "*brani*" } | Format-List DisplayName, Database, DisconnectReason
###### Wed Sep 19 12:36:23 AEST 2018 exchange
Get-Mailbox -ResultSize unlimited | Get-MailboxJunkEmailConfiguration | Where-Object {$_.Enabled -eq $False}
###### Tue Sep 25 16:25:18 AEST 2018 exchange quota
Set-Mailbox username@abc.com.au -Type shared -ProhibitSendReceiveQuota 9.4GB -ProhibitSendQuota 9.2GB -IssueWarningQuota 9GB -UseDatabaseQuotaDefaults $False
###### Tue Oct 2 14:06:05 AEST 2018 verify whether protocol logging form ms
Write-Host "Send Connectors:" -ForegroundColor yellow; Get-SendConnector | Format-List Name, ProtocolLoggingLevel; Write-Host "Receive Connectors:" -ForegroundColor yellow; Get-ReceiveConnector | Format-List Name, TransportRole, ProtocolLoggingLevel; Write-Host "Mailbox Transport Delivery service:" -ForegroundColor yellow; Get-MailboxTransportService | Format-List *ProtocolLoggingLevel; Write-Host "Front End Transport service:" -ForegroundColor yellow; Get-FrontEndTransportService | Format-List *ProtocolLoggingLevel; Write-Host "Transport service and Mailbox Transport Submission service:" -ForegroundColor yellow; Get-TransportService | Format-List *ProtocolLoggingLevel
###### Tue Oct 2 14:07:10 AEST 2018 verify logging files
Write-Host "Front End Transport service:" -ForegroundColor yellow; Get-FrontEndTransportService | Format-List ReceiveProtocolLog*, SendProtocolLog*; Write-Host "Mailbox Transport Submission and Mailbox Transport Delivery services:" -ForegroundColor yellow; Get-MailboxTransportService | Format-List ReceiveProtocolLog*, SendProtocolLog*; Write-Host "Transport service:" -ForegroundColor yellow; Get-TransportService | Format-List ReceiveProtocolLog*, SendProtocolLog*
###### Tue Sep 11 15:25:03 AEST 2018 powershell exchange defaul shortcut command
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noexit -command ". 'C:\Program Files\Microsoft\Exchange Server\V15\bin\RemoteExchange.ps1'; Connect-ExchangeServer -auto -ClientApplication:ManagementShell "
###### Tue Sep 11 15:32:38 AEST 2018 exchange count mailbox created by year
Get-Mailbox -server ex01 -Identity *store  | Select-Object alias, UserPrincipalName, whencreated, RecipientType, RecipientTypedetails |  Sort-Object whencreated -Descending | Group-Object {$_.whencreated.date.year} -NoElement
###### Thu Oct 11 11:10:48 AEDT 2018 General snapin
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010;
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;
Get-MessageTrackingLog -ResultSize Unlimited -Start ((Get-Date).AddMinutes(-10)) -EventId "Fail" -Recipients "dgm@company.com.au" -sender | Select-Object Timestamp,sender,recipients,messagesubject | Sort-Object timestamp
Get-MailboxJunkEmailConfiguration -Identity dgm@abc.com.au -ResultSize unlimited | out-file c:\temp\list.txt -Width 1000
Get-MailboxJunkEmailConfiguration -Identity dgm@abc.com.au -TrustedSendersAndDomains @{Add = "ato.gov.au", "INDAdvice@ato.gov.au", "noreply@ato.gov.au"}
Set-MailboxSentItemsConfiguration "Mailbox Name" -SendAsItemsCopiedTo SenderAndFrom -SendOnBehalfOfItemsCopiedTo SenderAndFrom
Get-Mailbox -RecipientTypeDetails SharedMailbox | Set-Mailbox -MessageCopyForSentAsEnabled $true -MessageCopyForSendOnBehalfEnabled $true
Get-MailboxStatistics [username] | Format-Table DisplayName, TotalItemSize, ItemCount
###### Thu Oct 11 11:09:02 AEDT 2018 check database white space
Get-Mailbox | Group-Object -Property:Database | Select-Object Name, Count | Sort-Object Name | Format-Table -Auto
Get-Mailbox -resultsize:unlimited | group-object -property:database
Get-MailBoxDatabase -status | Format-Table Name, DatabaseSize, AvailableNewMailboxSpace -auto
Get-MailboxDatabaseCopyStatus | Select-Object ContentIndexState, ContentIndexErrorMessage | Format-List
Set-MailboxDatabase "Database Name" -IndexEnabled $False
###### Thu Oct 11 11:54:04 AEDT 2018 mailbox size
Get-MailboxStatistics -Server ahex01 |Sort-Object totalitemsize -Descending |Select-Object displayname, itemcount, totalitemsize, messagetabletotalsize, attachmenttabletotalsize, mailboxtypedetail, servername, database | Out-GridView
get-mailbox -filter * | Select-Object alias, samaccountname, displayname, userprincipalname, primarysmtpaddress, organizationalunit, recipienttypedetails , servername, accountdisabled, whencreated, whenchanged | Out-GridView
###### Fri Oct 12 12:11:22 AEDT 2018 update oab
Get-AddressList | Update-AddressList
Get-GlobalAddressList | Update-GlobalAddressList
Get-OfflineAddressBook | Update-OfflineAddressBook
###### Fri Oct 12 12:20:29 AEDT 2018 send as DistributionGroup
Get-DistributionGroup "Group" | Add-ADPermission -User "User" -ExtendedRights "Send As"
###### Thu Oct 18 15:13:18 AEDT 2018 resource mailbox
get-mailbox -filter {Resourcetype -eq "Room"}
###### Thu Oct 18 16:02:35 AEDT 2018 search mailbox permission
$mailboxes = get-mailbox -filter {Resourcetype -eq "Room"}
#$mailboxes = get-mailbox -filter {RecipientTypeDetails -eq "RoomMailbox"}
foreach ($mailbox in $mailboxes) {
    (Get-MailboxPermission $mailbox) | Where-Object {($_.user).rawidentity -like "*kar*"} | Select-Object user, accessrights, identity | Format-Table -Wrap
}
###### Thu Oct 18 16:10:50 AEDT 2018 calendar
Add-MailboxFolderPermission -identity “Managingdirector:\Calendar” -user “personalassistant” -AccessRights editor
###### Tue Nov 13 13:06:48 AEDT 2018 mailbox permissions
Add-MailboxPermission -Identity Dolores-Toyota -User lauram -AccessRights fullaccess
###### Thu Oct 18 16:20:39 AEDT 2018 search mailbox permission
$mailboxes = get-mailbox -filter {RecipientTypeDetails -eq "UserMailbox"}
foreach ($mailbox in $mailboxes) {
    Get-MailboxFolderPermission ($mailbox.Alias + ":\Calendar") -ErrorAction SilentlyContinue | Where-Object {($_.user).displayname -like "*karley*"}  | Select-Object user, accessrights, Identity | Format-Table -AutoSize -Wrap
}
###### Mon Oct 22 14:22:51 AEDT 2018 convert to share
Set-Mailbox info@domain.com -Type shared -ProhibitSendReceiveQuota 10GB -ProhibitSendQuota 9.5GB -IssueWarningQuota 9GB
###### Fri Oct 26 21:28:23 AEDT 2018 vitrual directorys
Get-OwaVirtualDirectory -Server $server | Select-Object InternalUrl,ExternalUrl
Get-EcpVirtualDirectory -Server $server | Select-Object InternalUrl,ExternalUrl
Get-ActiveSyncVirtualDirectory -Server $server | Select-Object InternalUrl,ExternalUrl
Get-WebServicesVirtualDirectory -Server $server | Select-Object InternalUrl,ExternalUrl
Get-OabVirtualDirectory -Server $server | Select-Object InternalUrl,ExternalUrl
Get-MapiVirtualDirectory -Server $server | Select-Object InternalUrl,ExternalUrl
Get-OutlookAnywhere -Server $server | Select-Object ExternalHostname,InternalHostname,ExternalClientsRequireSsl,InternalClientsRequireSsl
Get-ClientAccessService -Identity $server | Select-Object AutoDiscoverServiceInternalUri
###### Mon Nov 5 10:40:17 AEDT 2018 get deailted mailbox folders usage
Get-MailboxFolderstatistics -identity leim  | Select-Object identity, foldersize | Sort-Object foldersize -Descending | Out-GridView
###### Mon Nov 5 10:46:16 AEDT 2018 get general mailbox usage
Get-MailboxStatistics -Identity justins | Format-List *name*, *size*, *count*
###### Mon Nov 5 16:25:48 AEDT 2018 get mailbox status combine with mailbox
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;
Get-Mailbox -ResultSize Unlimited | Foreach-Object{
    $mbx = $_ | Select-Object DisplayName, UserPrincipalName, whencreated
    $stats = Get-MailboxStatistics $_ | Select-Object LastLogonTime, totalitemsize
    New-Object -TypeName PSObject -Property @{
        name = $mbx.DisplayName
        UserPrincipalName = $mbx.UserPrincipalName
        Created = $mbx.whencreated
        lastlogon = $stats.LastLogonTime
        Size = $stats.TotalItemSize
    }
} | Export-Csv c:\temp\mailbox.csv -NoTypeInformation
###### Thu Nov 29 14:32:50 AEDT 2018 export user mailbox folder
#NOT TESTED
#colins\Inbox\01 Sales Leads
New-ManagementRoleAssignment -Role “Mailbox Import Export” -SecurityGroup AdGroup
New-MailboxExportRequest -mailbox colins -includefolders "#inbox#/01 Sales Leads/*" -FilePath \\ahdc02\scanned\01_Sales_Lead.pst
New-MailboxExportRequest -mailbox colins -SourceRootFolder  "Inbox" -includefolders "01 Sales Leads/*" -FilePath \\ahdc02\scanned\01_Sales_Lead.pst
New-MailboxExportRequest -mailbox colins -SourceRootFolder  "Inbox/01 Sales Leads"  -FilePath \\ahdc02\scanned\01_Sales_Leads.pst
#01 Sales Leads becomes root folder
#"#inbox#/*"
###### Thu Nov 29 15:31:35 AEDT 2018 export
New-MailboxExportRequest -Mailbox mailtst -FilePath \\HQ-FS01\ExportPST\mailtst.pst
New-MailboxExportRequest -Mailbox mailtst -FilePath \\HQ-FS01\ExportPST\mailtst.pst -IncludeFolders "#Inbox#"
New-MailboxExportRequest -Mailbox mailtst -FilePath \\HQ-FS01\ExportPST\mailtst.pst -ExcludeFolders "#DeletedItems#"
New-MailboxExportRequest -Mailbox mailtst -FilePath \\HQFS01\ExportPST\mailtst.pst -ContentFilter {(body –like “*MSProject*”) –and (body –like “*London*”) –and (Received –lt “01/01/2015”)}
###### Thu Nov 29 15:31:42 AEDT 2018 import
New-MailboxImportRequest -Mailbox usetest -FilePath \\HQ-FS01\PST\usetest.pst
New-MailboxImportRequest -Mailbox usetest -FilePath \\HQ-FS01\PST\usetest.pst -TargetRootFolder “Old_mail” -IncludeFolders "#Inbox#"
Get-MailboxImportRequest | Get-MailboxImportRequestStatistics
Get-MailboxExportRequest -Status Completed | Remove-MailboxExportRequest
###### Thu Nov 29 16:12:27 AEDT 2018 export permission, group array expend
Get-mailbox | Get-MailboxPermission | Where-Object{($_.IsInherited -eq $False) -and -not ($_.User -match “NT AUTHORITY”)} |Select-Object User,Identity,@{Name=”AccessRights”;Expression={$_.AccessRights}} | Export-csv C:\mailboxPermission.csv
###### Thu Nov 29 16:16:06 AEDT 2018 hidden mailbox
Get-Mailbox -ResultSize unlimited | Where-Object{$_.HiddenFromAddressLissEnabled -eq $true}
###### Thu Nov 29 16:16:12 AEDT 2018 hidden DL
Get-DistributionGroup -resultsize unlimited| Where-Object{$_.HiddenFromAddressLissEnabled -eq $true}
###### Thu Nov 29 16:17:05 AEDT 2018 maxed quota limits
Get-MailboxStatistics -Server Servername| Where-Object{($_.StorageLimitStatus -contains “IssueWarning”) -or ($_.StorageLimitStatus -contains “ProhibitSend”)}
###### Thu Nov 29 16:17:17 AEDT 2018 not default quota limits
Get-Mailbox -ResultSize unlimited |Where-Object{($_.UseDatabaseQuotaDefaults -eq $false)}
###### Fri Nov 30 14:33:10 AEDT 2018 get all distribution list memebers
$dist = foreach ($group in (Get-DistributionGroup -Filter {name -like "*"})) {Get-DistributionGroupMember $group | Select-Object @{Label="Group";Expression={$Group.Name}},@{Label="User";Expression={$_.Name}},SamAccountName}
$dist | Sort-Object Group,User | Export-Csv c:\temp\a.csv
# my version without varible
Invoke-Command {foreach ($group in (Get-DistributionGroup -Filter {name -like "*"})) { Get-DistributionGroupMember $group | Select-Object @{Label="Group";Expression={$Group.Name}},@{Label="User";Expression={$_.Name}},SamAccountName } } | Sort-Object Group,User
