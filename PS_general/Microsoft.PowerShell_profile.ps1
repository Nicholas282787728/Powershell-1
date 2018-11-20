#Clear-Host
#Start-Process powershell -Verb runAs
# Welcome message

$time = Get-Date -Format g

$a = $host.ui.RawUI.WindowTitle -replace " -.*", ""
$host.ui.RawUI.WindowTitle = $a +  " - " + $env:COMPUTERNAME + " - " +  $env:userdomain + "\" +$env:Username + " - " + $time

# $host.ui.RawUI.WindowTitle += " - " + $env:COMPUTERNAME + " - " + $env:Username + " - " + $time

Get-ChildItem C:\temp\PS_transcripts -Filter *.txt | Where-Object {$_.Length -lt 1000} | Remove-Item
Start-Transcript -OutputDirectory C:\temp\PS_transcripts
Set-Item -Path function:prompt -Value {'PS [' + $(Get-Date -Format t) + "] " + $(Get-Location) + '> '}
Set-Location $env:SystemDrive\