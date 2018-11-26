# convert pfx to pem
openssl pkcs12 -in "path.pfx" -out "newfile.pem" -nodes
###### Mon Nov 26 12:21:07 AEDT 2018 add route
sudo ip route add 10.255.255.0/24 via 10.20.11.252 dev ens160