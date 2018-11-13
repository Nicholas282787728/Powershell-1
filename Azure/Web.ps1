###### Tue Nov 13 23:44:40 AEDT 2018 web diagnostics logs
Set-AzureRmWebApp -HttpLoggingEnabled 1
Set-AzureRmWebApp -RequestTracingEnabled $true -name Verapp1
###### Wed Nov 14 00:43:09 AEDT 2018 web diagnostics logs
Set-AzureWebSite -HttpLoggingEnabled 1
Enable-AzureWebsiteApplicationDiagnostic -BlobStorage -LogLevel Error
Set-AzureWebSite -RequestTracingEnabled $true -name VerApp1
###### Wed Nov 14 00:41:00 AEDT 2018
Switch-AzureRmWebAppSlot