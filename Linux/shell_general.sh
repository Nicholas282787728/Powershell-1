# convert pfx to pem
openssl pkcs12 -in "path.pfx" -out "newfile.pem" -nodes
###### Mon Nov 26 12:21:07 AEDT 2018 add route
sudo ip route add 10.255.255.0/24 via 10.20.11.252 dev ens160
###### Mon Nov 26 15:22:58 AEDT 2018 lock an account
usermod -L <user_name>
###### Mon Nov 26 15:23:08 AEDT 2018 clean apt repo
sudo apt autoremove
###### Wed Nov 28 23:33:46 AEDT 2018 shutdown
sudo shutdown -P -h now