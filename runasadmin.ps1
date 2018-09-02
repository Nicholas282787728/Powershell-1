
$proc = cmd

<#
powershell
powershell_ise
cmd
code
 #>

Start-Process   $proc -verb runas

#or create a powershell shortcut
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "start-process powershell -verb runas"

