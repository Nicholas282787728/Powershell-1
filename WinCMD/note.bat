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