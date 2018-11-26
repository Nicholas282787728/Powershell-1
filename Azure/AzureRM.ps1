###### Mon Nov 26 23:25:38 AEDT 2018
Connect-AzureRmAccount -Credential (Import-Clixml C:\temp\azure.cred)
###### Mon Nov 26 23:27:30 AEDT 2018
Get-AzureRmTenant; Get-AzureRmContext
###### Wed Sep 19 11:42:10 AEST 2018 o365
Install-Module -name AzureAD      # azureAD objects and user and etc
Install-Module msonline   # azureAD users,sso,domain management etc, sharepoint
Install-Module Azurerm      #azure cloud resource manager
Install-Module azure        #classic azure cloud
###### Tue Nov 13 23:53:14 AEDT 2018 other modules
Install-Module CredentialManager
Install-Module PackageManagement #installed by default
Install-Module PowerShellGet #installed by default
###### Wed Oct 24 16:46:13 AEDT 2018 site recovery - deployment planner tool
# profiling
C:\Users\Administrator\Desktop\ASR Deployment Planner-v2.2>ASRDeploymentPlanner.exe -Operation StartProfiling -Virtualization VMware -Directory "d:\vc_ProfiledData" -Server 10.1.1.1 -VMListFile "c:\users\Administrator\Desktop\vmlist.txt"  -NoOfMinutesToProfile 60  -user dc\svcazure
#-NoOfHoursToProfile -NoOfDaysToProfile
###### Thu Oct 25 09:15:40 AEDT 2018 gen report
ASRDeploymentPlanner.exe -Operation GenerateReport -Virtualization VMware -Server 10.255.255.21 -Directory "d:\vc_ProfiledData" -VMListFile “c:\users\Administrator\Desktop\vmlist.txt”


