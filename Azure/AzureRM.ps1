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
###### Wed Nov 28 15:08:56 AEDT 2018 move resource to resource groups
Get-AzureRmResource -ResourceGroupName default | Move-AzureRmResource -DestinationResourceGroupName lan
###### Thu Nov 29 22:35:58 AEDT 2018 remove vm
Get-AzureRmResource -ResourceGroupName ilb | Where-Object name -like vm2* | Remove-AzureRmResource -force -AsJob
###### Thu Nov 29 22:40:02 AEDT 2018 deploy from templet
Select-AzureRmSubscription -SubscriptionName yourSubscriptionName
New-AzureRmResourceGroup -Name ExampleResourceGroup -Location "AustraliaEast"
# deploy from local templet
New-AzureRmResourceGroupDeployment -Name ExampleDeployment -ResourceGroupName ExampleResourceGroup `
    -TemplateFile c:\MyTemplates\storage.json -storageAccountType Standard_GRS
# deploy from external source
New-AzureRmResourceGroup -Name ExampleResourceGroup -Location "AustraliaEast"
New-AzureRmResourceGroupDeployment -Name ExampleDeployment -ResourceGroupName ExampleResourceGroup `
    -TemplateUri https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/101-storage-account-create/azuredeploy.json `
    -storageAccountType Standard_GRS

