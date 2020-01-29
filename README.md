# SigFW
Open Source SS7/Diameter firewall

## SigFW introduction
* [SigFW BlackHat USA 2017 Presentation](https://github.com/P1sec/SigFW/blob/master/docs/us-17-Kacer-SS7-Attacker-Heaven-Turns-Into-Riot-How-To-Make-Nation-State-And-Intelligence-Attackers-Lives-Much-Harder-On-Mobile-Networks.pdf)
* [SigFW BlackHat USA 2017 Whitepaper](https://github.com/P1sec/SigFW/blob/master/docs/us-17-Kacer-SS7-Attacker-Heaven-Turns-Into-Riot-How-To-Make-Nation-State-And-Intelligence-Attackers-Lives-Much-Harder-On-Mobile-Networks-wp.pdf)
* [SigFW BlackHat USA 2017 Talk (youtube)](https://www.youtube.com/watch?v=XiKq2fJBUJI)

## Build instructions
For more detailed installation and build instructions refer to this [page](https://github.com/P1sec/SigFW/wiki/Installation-and-Build-Instructions).

### Prerequisities
Install Maven
(Optional) Netbeans IDE for developers

### Clone source code
git clone https://github.com/P1Sec/SigFW

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

![](https://github.com/P1sec/SigFW/blob/master/docs/running_from_netbeans.gif)


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
SigFW is licensed under dual license policy. The default license is the Free Open Source GNU Affero GPL v3.0. Alternatively a commercial license can be obtained from P1 Security S.A.S.

## Attribution
For the list of contributors, see the AUTHORS file.

Original work was created by Martin Kacer, Philippe Langlois

Copyright 2020, P1 Security S.A.S and individual contributors

We would like to thanks for everyone supporting this project.

