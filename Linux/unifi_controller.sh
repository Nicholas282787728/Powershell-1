mkdir  <version>
wget http://
sudo dpkg  -i file.deb
sudo apt-get -f install
# run controller as service on windows
cd "%UserProfile%\Ubiquiti UniFi\"
java -jar lib\ace.jar installsvc
java -jar lib\ace.jar startsvc

https://localhost:8443

UDP	3478	Port used for STUN.
TCP	8080	Port used for device and controller communication.
TCP	8443	Port used for controller GUI/API as seen in a web browser
TCP	8880	Port used for HTTP portal redirection.
TCP	8843	Port used for HTTPS portal redirection.
TCP	6789	Port used for UniFi mobile speed test.
TCP	27117	Port used for local-bound database communication.
UDP	5656-5699	Ports used by AP-EDU broadcasting.
UDP	10001	Port used for AP discovery
UDP	1900	Port used for "Make controller discoverable on L2 network" in controller settings.
