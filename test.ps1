param(
    #[string] $server = (Read-Host "hostname"),
    [array]$servers = @("tpdc01", "tpex01", "tporcl01", "tpvbr01", "rds01"),
    [array]$exchangeservers = @()
)
Write-Host $servers[0]
Write-Host $servers[1]




