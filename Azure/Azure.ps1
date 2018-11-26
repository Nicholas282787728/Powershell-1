###### Wed Oct 24 15:29:22 AEDT 2018  azure ad msol
$cred = Get-Credential
Connect-MsolService -Credential $cred

# check status of dir sync
(Get-MsolCompanyInformation).directorysynchronizationenabled

Set-MsolDirSyncEnabled -EnableDirSync $true

###### Fri Sep 14 13:58:31 AEST 2018 azure      ad sync
Import-Module ADSync
Start-ADSyncSyncCycle -PolicyType Delta
Start-ADSyncSyncCycle -PolicyType Initial

###### Fri Sep 14 14:17:07 AEST 2018 o365 powershell###### Mon Sep 17 08:45:16 AEST 2018
Install-Module -Name AzureAD
Connect-AzureAD     # azuread
Connect-MsolService     #azure sharepoint
Connect-AzureRmAccount      #azure cloud
Get-AzureRmTenant
Get-AzureRmContext

###### Wed Sep 19 11:42:10 AEST 2018 o365
Install-Module AzureAD      # azureAD objects and user and etc
Install-Module msonline   # azureAD users,sso,domain management etc,
Install-Module Azurerm      #azure cloud resource manager
Install-Module azure        #classic azure cloud
###### Tue Nov 13 23:53:14 AEDT 2018 other modules
Install-Module CredentialManager
Install-Module MSOnline
Install-Module PackageManagement #installed by default
Install-Module PowerShellGet #installed by default
###### Mon Nov 12 12:52:51 AEDT 2018 exchange online
$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
Import-PSSession $Session -DisableNameChecking
Connect-MsolService -Credential $UserCredential
#! convert to shared mailbox and setup quota
Get-Mailbox -identity engineering@domainname.com | set-mailbox -type “Shared”
Set-Mailbox engineering@domainname.com -ProhibitSendReceiveQuota 50GB -ProhibitSendQuota 49.75GB -IssueWarningQuota 49.5GB
#! assign permissions to shared mailbox
Add-MailboxPermission engineering@domainname.com -User "Engineering Group" -AccessRights FullAccess
#! remove o365 license
Connect-MsolService
$MSOLSKU = (Get-MSOLUser -UserPrincipalName engineering@domainname.com).Licenses[0].AccountSkuId
Set-MsolUserLicense -UserPrincipalName engineering@domainname.com -RemoveLicenses $MSOLSKU

Get-Mailbox -Identity wii | Format-List *type*

###### Wed Oct 24 16:46:13 AEDT 2018 site recovery - deployment planner tool
# vmware vcentre connection
Connect-VIServer -Server vcentre -User user -Password password
Get-VM |  Select-Object Name | Sort-Object -Property Name  outputfile.txt
# profiling
C:\Users\Administrator\Desktop\ASR Deployment Planner-v2.2>ASRDeploymentPlanner.exe -Operation StartProfiling -Virtualization VMware -Directory "d:\vc_ProfiledData" -Server 10.1.1.1 -VMListFile "c:\users\Administrator\Desktop\vmlist.txt"  -NoOfMinutesToProfile 60  -user dc\svcazure
#-NoOfHoursToProfile -NoOfDaysToProfile
###### Thu Oct 25 09:15:40 AEDT 2018 gen report
ASRDeploymentPlanner.exe -Operation GenerateReport -Virtualization VMware -Server 10.255.255.21 -Directory "d:\vc_ProfiledData" -VMListFile “c:\users\Administrator\Desktop\vmlist.txt”


