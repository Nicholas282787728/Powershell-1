# vmware vcentre connection
Connect-VIServer -Server vcentre -User user -Password password
Get-VM |  Select-Object Name | Sort-Object -Property Name  outputfile.txt