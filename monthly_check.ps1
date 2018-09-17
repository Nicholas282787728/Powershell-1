<#
Logs
FreeDiskSpace
exchange health test - mailflow and Queues
EXCHANGE mailbox store and mailboxes
BPA
WAN test
Email sent out the result
WSUS - UPDATES approval
AD/LDAP
DNS
WINS
DHCP
VEEAM BACKUP STATUS CHECK
#>

param(
   # [string] $servers = (Read-Host "hostname")
    [array]$servers = @()
    [array]$exchangeservers = @()
    )
Write-Host $servers[0]


###### Mon Sep 17 11:42:30 AEST 2018  freediskspace
Invoke-Command -ComputerName tpdc01, tpex01, tporcl01, tpvbr01, rds01 {`
        get-wmiobject win32_volume | `
        Where-Object { $_.DriveType -eq 3 -and $_.Label -notlike "System Reserved"} | `
        ForEach-Object { get-psdrive $_.DriveLetter[0] }} | `
    Sort-Object pscomutpername, Root


$output = "C:\temp\abc.txt"
Get-Date -Format g | out-file $output -Append; `
    Get-MailboxDatabase -status | Format-List | out-file $output -Append ; `
    get-mailboxstatistics -Server tpex01 | `
    Add-Member -MemberType ScriptProperty -Name TotalItemSizeinMB -Value {$this.totalitemsize.value.ToMB()} -PassThru |`
    Sort-Object totalitemsize, lastlogontime | `
    Format-Table DisplayName, itemcount, totalitemsize, lastlogontime -AutoSize | `
    out-file $output -Append

Get-WsusComputer | Sort-Object last*
Get-WsusUpdate -Classification Critical, Security -Approval Unapproved -Status FailedOrNeeded | Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"


Get-WsusUpdate -Classification Critical, Security -Approval Unapproved -Status FailedOrNeeded | Approve-WsusUpdate -Action Install -TargetGroupName "windows 7 pro"