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
    #[string] $server = (Read-Host "hostname"),
    [array]$servers = @("tpdc01", "tpex01", "tporcl01", "tpvbr01", "rds01"),
    [array]$exchangeserver = @("tpex01.tpdlawyers.local"),
    $outputfile = "C:\temp\$(Get-Date -UFormat %Y%m%d-%H%M).txt"
)

function output-file {
    Out-File -FilePath $outputfile -Encoding ascii -Append
}

if (-not (Test-Path c:\temp)) {new-item c:\temp -ItemType Directory -Force}
"[$(Get-Date -Format g)]" | Out-File -FilePath $outputfile -Encoding ascii -Append

###### Mon Sep 17 11:42:30 AEST 2018  freediskspace
<# Invoke-Command -ComputerName $servers {`
        get-wmiobject win32_volume | `
        Where-Object { $_.DriveType -eq 3 -and $_.Label -notlike "System Reserved"} | `
        ForEach-Object { get-psdrive $_.DriveLetter[0] }} | `
    Sort-Object pscomutpername, Root #>

#! diskspace
$diskusage = get-wmiobject Win32_LogicalDisk -ComputerName $servers -Filter "DriveType=3"  | `
    Select-Object systemname, Name, volumename, FileSystem, FreeSpace, BlockSize, Size | `
    ForEach-Object {$_.BlockSize = (($_.FreeSpace) / ($_.Size)) * 100; $_.FreeSpace = ($_.FreeSpace / 1GB); $_.Size = ($_.Size / 1GB); $_} | `
    Format-Table systemname, Name, volumename, @{n = 'FS'; e = {$_.FileSystem}}, @{n = 'Free(Gb)'; e = {'{0:N2}' -f $_.FreeSpace}}, @{n = '%Free'; e = {'{0:N2}' -f $_.BlockSize}}, @{n = 'Capacity(Gb)'; e = {'{0:N2}' -f $_.Size}} -AutoSize
Out-File -FilePath $outputfile -InputObject $diskusage -Encoding ascii -Append
#! exchange status
    $exchSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://tpex01.tpdlawyers.local/PowerShell/ -Authentication Kerberos -Credential (Get-StoredCredential -Target $exchangeserver)
    Import-PSSession $exchSession -DisableNameChecking
    Get-MailboxDatabase -Server $exchangeserver -status | Format-List | Add-Content $outputfile -Encoding Ascii;
    get-mailboxstatistics -Server $exchangeserver | `
         Add-Member -MemberType ScriptProperty -Name TotalItemSizeinMB -Value {$this.totalitemsize.value.ToMB()} -PassThru |`
         Sort-Object totalitemsize, lastlogontime | `
         Format-Table DisplayName, itemcount, totalitemsize, lastlogontime -AutoSize | Add-Content $outputfile -Encoding Ascii;
    Test-ServiceHealth | Add-Content $outputfile -Encoding Ascii

#! wsus
Get-WsusComputer | Sort-Object last*
Get-WsusUpdate -Classification Critical, Security -Approval Unapproved -Status FailedOrNeeded | Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"
