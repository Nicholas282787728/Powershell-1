$app = Get-WmiObject -Class Win32_Product | Where-Object { 
    $_.Name -like "auskey" 
}
$app
$app.Uninstall()


Get-WmiObject -Class Win32_Product  | Out-GridView








Import-Certificate -Filepath ".\gratex.cert" -CertStoreLocation Cert:\LocalMachine\CA