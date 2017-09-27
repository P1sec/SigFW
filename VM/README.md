Ubuntu pre-built VM can be obtained from h21.lab.contact@gmail.com

VM is packaged including the following:
* SS7FW
* tshark + Elasticsearch

The SSH banner in the VM includes the quick instruction how to use the VM:
```
SigFW
Open Source SS7/Diameter firewall
Copyright 2017, H21 lab, P1 Security and by all individual authors and contributors
See the AUTHORS in the for a full listing of authors and contributors.

SigFW is licensed under dual license policy. The default license is
the Free Open Source GNU Affero GPL v3.0.


Interfaces:
   enp0s3 - management (SSH, Web)
   enp0s8 - signalling (SigFW could be reconfigured here)
   enp0s9 - passive signalling (port-mirrored traffic)

To access Kibana:
   http://<host>:5601/

To access API
   https://<host>:8443/ss7fw_api/1.0/get_status

To check if services are running:
   sudo service tshark_to_ss7fw status
   sudo service tshark_to_ek status
   sudo service ss7fw status
   sudo service ss7server status
   sudo service ss7client status

To replay the pcap on passive interface:
   sudo tcpreplay  --intf1=enp0s9 sigtran.pcap

Description:
   By default only SS7FW is enabled. The SS7FW is in passive mode.
   DiameterFW code is present but configured as service system service.
   Tshark is capturing traffic on enp0s9 and pushing into ElasticSearch.
   Second instance of tshark is pushing capture into named pipe of SS7FW.
   The SS7FW consist of ss7client, ss7firewall, ss7server. ss7client replay
   the captured traffic from enp0s9 towards ss7firewall and ss7server on
   localhost.

   SS7FW is located in /opt/SigFW/ss7fw/
   DiameterFW is located in /opt/SigFW/diameterfw/

   Before first run or if the IP has changed, modify /etc/kibana/kibana.yml

To access logs:
   tail -f /opt/SigFW/ss7fw/ss7fw.ss7fw-core_jar_1.0.0-SNAPSHOT/ss7fw.log
```
