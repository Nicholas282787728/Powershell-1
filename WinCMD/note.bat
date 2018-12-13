repadmin /syncall /APed dc=domain,dc=com  - Directory partition
repadmin /syncall /APed cn=configuration,dc=domain,dc=com  - Configuration Partition
repadmin /syncall /APed cn=schema, cn=configuration,dc=domain,dc=com  - Schema Partition
###### Mon Nov 26 17:21:39 AEDT 2018 query FSMO, PDC
NetDOM /query FSMO

repadmin /replsummary
repadmin /queue
Repadmin /Showrepl


nslookup abc 8.8.8.8
set debug=yes
set norecurse
wuauclt /detectnow
wuauclt /reportnow

gpupdate /force /target:computer

wmic
/node:TargetComputerNameHere product get name, version, vendor

wbemtest.exe
rem launch unifi controller
c:\Program Files (x86)\Java\jre1.8.0_151\bin>javaw.exe -jar "C:\Users\user\Ubiquiti UniFi\lib\ace.jar" ui
rem for unifi discover
java -jar <unifi_base>/lib/ace.jar discover

rem wmic for software installation
wmic
/node:tpw704 product get name,version,vendor
rem active office
cscript OSPP.VBS /inpkey:KEY-KEY-KEY COMPUTERNAME
cscript OSPP.VBS /act COMPUTERNAME

rem remove kb
wusa /uninstall /kb:2506143 /norestart

rem diskshadow
DISKSHADOW> set verbose on
DISKSHADOW>
DISKSHADOW> set context volatile
DISKSHADOW> add volume c:
DISKSHADOW> add volume d:
DISKSHADOW> begin backup
DISKSHADOW> create
DISKSHADOW> end backup

rem djoin
djoin /provision /domain abc.local /machine ws01 /savefile c:\temp\ws01.txt
djoin /requestodj /loadfile c:\temp\ws01.txt /windowspath %windir% /localos

rem add new user
net user username <password> /add /expires:never /active:yes
wmic useraccount WHERE Name='ACCOUNTNAME' set PasswordExpires=false
wmic useraccount WHERE Name='ACCOUNTNAME' set PasswordChangeable=false
wmic useraccount WHERE "Name='%username%'" set PasswordExpires=false
rem net accounts /MaxPWAge:unlimited
rem reset password
net user username <password>
rem add into admin
net localgroup administrators username /add
rem test
runas /user:domain\username cmd
rem route
route add 10.255.255.0 mask 255.255.255.0 192.168.12.252 metric 100 -p
rem map drive
net use \\192.168.175.129\c$ /user:win7-2\admin *
rem switch o365 to monthly channel
cd C:\Program Files\Common Files\Microsoft Shared\ClickToRun\
OfficeC2RClient.exe /changesetting Channel=Monthly
OfficeC2RClient.exe /update user

rem wmic serial number
wmic bios get serialnumber
wmic csproduct get vendor, version
wmic computersystem get model,name,manufacturer,systemtype
rem find CA in AD
certutil -config - -ping
rem ad sync
repadmin /syncall /AdeP
rem get system sid
wmic useraccount get name,sid

rem join domain command
netdom /domain:ah.local /user:leim /password:nottelling member <computer name> /joindomain
rem o365 Reset Office 365 ProPlus activation state
C:\program files <x86>\Microsoft office\office16>cscript ospp.vbs /dstatus
C:\program files <x86>\Microsoft office\office16>cscript ospp.vbs /unpkey:7H3XC
rem route
route delete 0.0.0.0
route add 0.0.0.0 mask 0.0.0.0 192.168.43.1 Metric 25 if 26
rem route change
rem request certificate with templet
certreq.exe -submit -attrib "CertificateTemplate:WebServer" certifcatesigningrequest.csr
rem ad redirect and computer ou redirect
redirusr ou=myusers,DC=contoso,dc=com
redircmp ou=mycomputers,DC=contoso,dc=com
rem sysprep
%WINDIR%\system32\sysprep\sysprep.exe /generalize /shutdown /oobe
rem change between DL and SG
dsmod group GroupDN -secgrp {yes|no}
rem disk clean
cleanmgr /sageset:65535 /sagerun:65535
