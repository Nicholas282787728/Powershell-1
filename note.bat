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