###### Tue Nov 13 23:44:40 AEDT 2018 web diagnostics logs
Set-AzureWebSite -HttpLoggingEnabled 1
Enable-AzureWebsiteApplicationDiagnostic -BlobStorage -LogLevel Error
Set-AzureWebSite -RequestTracingEnabled $true -name VerApp1
