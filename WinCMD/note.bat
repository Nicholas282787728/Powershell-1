repadmin /syncall /APed dc=domain,dc=com  - Directory partition
repadmin /syncall /APed cn=configuration,dc=domain,dc=com  - Configuration Partition
repadmin /syncall /APed cn=schema, cn=configuration,dc=domain,dc=com  - Schema Partition
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
net user localgroup administrators username /add
rem test
runas /user:domain\username cmd

