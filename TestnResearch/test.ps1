param(
    #[string] $server = (Read-Host "hostname"),
    [array]$servers = @("tpdc01", "tpex01", "tporcl01", "tpvbr01", "rds01"),
    [array]$exchangeservers = @()
)
Write-Host $servers[0]
Write-Host $servers[1]


$a = Get-WmiObject Win32_Bios -Computer localhost
$a | Format-List -Property Name, @{Label = "BIOS Age"; Expression = {(Get-Date) - $_.ConvertToDateTime($_.ReleaseDate)}}


Get-Date -Format F | Add-Content Test.txt
Get-Date -UFormat %Y%m%d-%H%M


$Breakout = $false

If ($Breakout -eq $true) {
    Write-Host "Break Out!"
    Break
}
ElseIf ($Breakout -eq $false) {
    Write-Host "No Breakout for you!"
}
Else {
    Write-Host "Breakout wasn't defined..."
}
Write-Host "abc"


$c=0
1..10 |   ForEach-Object { `
    $c++ ;`
  Write-Host $c }