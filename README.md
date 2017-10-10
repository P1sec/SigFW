# SigFW
Open Source SS7/Diameter firewall. This version is maintained by H21 lab.

## Build instructions

### Prerequisities
Install Maven

(Optional) Netbeans IDE for developers

### Clone source code
git clone https://github.com/H21lab/SigFW

### Build SigFW project
```bash
cd ./SigFW/sigfw/sigfw.sigfw
mvn clean install -Dmaven.test.skip=true
```

### Run SS7FW
```bash
mvn exec:java -Dexec.mainClass="ss7fw.SS7Firewall"
mvn exec:java -Dexec.mainClass="ss7fw.SS7ClientLiveInput"
mvn exec:java -Dexec.mainClass="ss7fw.SS7Server"
```

### Replay traffic from pcap
```bash
cd ./input
mkfifo pipe
tshark -T ek -x -j "" -r ./input/sigtran.pcap > sigtran.json
cat ./input/sigtran.json > pipe
```

![](https://github.com/H21lab/SigFW/blob/master/docs/running_from_netbeans.gif)


### Run DiameterFW
```bash
mvn exec:java -Dexec.mainClass="diameterfw.DiameterFirewall"
mvn exec:java -Dexec.mainClass="diameterfw.DiameterClientLiveInput"
mvn exec:java -Dexec.mainClass="diameterfw.DiameterServer"
```

### Replay traffic from pcap
```bash
cd ./input
mkfifo pipe
tshark -T ek -x -j "" -r ./input/diameter.pcap > diameter.json
cat ./input/diameter.json > pipe
```

### Security
For both SS7FW and DiameterFW before using.

realm.properties: Change the username, password for firewall API

sigfw.json: Generate new Public, Private Keys. Change the mThreat salt

Jetty: Change the certificate

### To test the encryption, signatures
Instead of SS7Firewall run SS7FirewallFirstInstance and SS7FirewallSecondInstance

Instead of DiameterFirewall run DiameterFirewallFirstInstance and DiameterFirewallSecondInstance

## Limitations
Program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY.

## License
SigFW is licensed under dual license policy. The default license is the Free Open Source GNU Affero GPL v3.0. Alternatively a commercial license for this fork can be obtained from H21 lab.

## Attribution
For the list of contributors, see the AUTHORS file.
Copyright 2017, H21 lab, P1 Security and by all individual authors and contributors

