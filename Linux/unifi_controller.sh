mkdir  <version>
wget http://
sudo dpkg  -i file.deb
sudo apt-get -f install
# run controller as service on windows
cd "%UserProfile%\Ubiquiti UniFi\"
java -jar lib\ace.jar installsvc
java -jar lib\ace.jar startsvc

