function Get-TimeStamp {
    return "[{0:dd/MM/yy} {0:HH:mm:ss}]" -f (Get-Date)
}

#Get-VBRTapeJob | where {$_.LastState -ne "Stopped"}| Stop-VBRJob | fl >> C:\Scripts\Logs\TapeInventory.log
Add-PSSnapin VeeamPSSnapin
Set-Location c:\scripts

Get-VBRTapeLibrary -Name "HP Ultrium 6-SCSI" | Start-VBRTapeInventory

$log = "C:\Scripts\Logs\TapeInventory.log"
#$mediapool = (Get-VBRTapeMediaPool | where name -Like "*tape*").name
$mediapool = "Free"
$drive = Get-VBRTapeDrive
$tape = $drive.Medium


  Move-VBRTapeMedium -Medium $tape -MediaPool $mediapool
  Write-Output "$(Get-TimeStamp) $($tape.name) has been moved into $($mediapool)" >> $log 


exit
