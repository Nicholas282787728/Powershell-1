
Get-Credential | Export-Clixml -Path "c:\temp\leiadmin.xml"
$cred = Get-Credential( Import-Clixml -Path "C:\temp\leimadmin.xml")

function get-diskinfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Alias('hostname')]
        [string[]]$computername
    )
    BEGIN{}
    PROCESS {
        if ($_ -ne $null){
            $computername = $_
        }
        foreach ($computer in $computername){
            $wmi_param = @{
                            'class' = 'win32_logicaldisk';
                            'filter' = 'drivetype = 3';
                            'computername' =$computer;
            }
            if ($computer -ne $Env:COMPUTERNAME){
                $wmi_param += @{
                                'Credential' = $cred
                }
            }
            Get-WmiObject @wmi_param  |
            Select-Object systemname, name, volumename,
                         @{n = 'FS'; e = {$_.FileSystem}},
                         @{n = 'Free(Gb)'; e = {'{0:N2}' -f ($_.FreeSpace / 1GB)}},
                         @{n = 'Free%'; e = {'{0:N2}' -f ((($_.FreeSpace) / ($_.Size)) * 100)}},
                         @{n = 'Capacity(Gb)'; e = {'{0:N2}' -f ($_.Size / 1GB)}}
        }
    }
    END{}
}


get-diskinfo lei_laptop,adam-pc

$cred = Get-Credential( Import-Clixml -Path "C:\temp\leimadmin.xml")
function get-computersysteminfo {
    param (
        [Parameter(Mandatory=$true)]
        [Alias('hostname')]
        [string[]]$computername

        #[psobject]$result
        #[string]$wmi_param=$null
    )
    BEGIN{}
    PROCESS {
        if ($_ -ne $null){
            $computername = $_
        }
        foreach ($computer in $computername){
            $wmi_param = @{
                            'Class' = 'win32_computersystem';
                            'ComputerName' =$computer;
            }
            if ($computer -ne $Env:COMPUTERNAME){
                $wmi_param += @{
                                'Credential' = $cred
                }
            }
            Get-WmiObject @wmi_param |
            select-object name,Manufacturer,Model
        }

    }
    END{}
}
get-computersysteminfo lei_laptop,adam-pc

function get-lastestsecuritylog {
    param (
        [string]$computername
    )
    Get-EventLog -LogName Security -Newest 50 -ComputerName $computername
}


function get-sysinfo {
    param (
        [string[]]$computername
    )
    PROCESS {
        foreach ($comp in $computername){
        $os = Get-WmiObject -Class win32_operatingsystem -ComputerName $comp
        $cs = Get-WmiObject -Class win32_computersystem -ComputerName $comp
        $bios = Get-WmiObject -Class win32_bios -ComputerName $comp

        $lastbootup = $os | select @{LABEL = 'LastBootUpTime'; EXPRESSION = {$_.ConverttoDateTime($_.lastbootuptime)}}

        $prop = [ordered]@{'computername'=$comp;
                            'osverion'=$os.version;
                            'spversion'=$os.servicepackmajorversion;
                            'mfgr'=$cs.manufacturer;
                            'model'=$cs.model;
                            'ram'=$cs.totalphysicalmemory;
                            'biosserial'=$bios.serialnumber;
                            'lastreboot'=$lastbootup;
                            'LastBootUpTime'= $os.lastbootuptime
                        }
        

        $obj = New-Object -TypeName psobject -Property $prop
        Write-Output $obj
        }
    }
}

get-sysinfo lei_laptop


get-lastestsecuritylog lei_laptop
get-computersysteminfo lei_laptop
get-diskinfo lei_laptop

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
    [string[]]$servers = @("tpdc01", "tpex01", "tporcl01", "tpvbr01", "rds01"),
    [string[]]$exchangeserver = @("tpex01.tpdlawyers.local"),
    $outputfile = "C:\temp\$(Get-Date -UFormat %Y%m%d-%H%M).txt"
)

function out-file {
    Out-File -FilePath $outputfile -Encoding ascii -Append
if (-not (Test-Path c:\temp)) {new-item c:\temp -ItemType Directory -Force}
"[$(Get-Date -Format g)]" | Out-File -FilePath $outputfile -Encoding ascii -Append

}



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
