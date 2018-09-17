#Clear-Host
#Start-Process powershell -Verb runAs
# Welcome message

$time = Get-Date -Format g
$host.ui.RawUI.WindowTitle += " - " + $env:COMPUTERNAME + " - " + $env:Username + " - " + $time


Get-ChildItem C:\temp\PS_transcripts -Filter *.txt | Where-Object {$_.Length -lt 1000} | Remove-Item

Start-Transcript -OutputDirectory C:\temp\PS_transcripts