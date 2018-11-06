/**
 * SigFW
 * Open Source SS7/Diameter firewall
 * By Martin Kacer, Philippe Langlois
 * Copyright 2017, P1 Security S.A.S and individual contributors
 * 
 * See the AUTHORS in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * 
 * This modules requires SS7FirewallFirstInstance and SS7FirewallSecondInstance to be running
 * Or alternatively  SS7Firewall to be running
 * 
 */
package ss7fw;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.mobicents.protocols.api.Association;
import org.mobicents.protocols.api.AssociationListener;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.api.ManagementEventListener;
import org.mobicents.protocols.api.PayloadData;
import org.mobicents.protocols.api.Server;
import org.mobicents.protocols.sctp.netty.NettyAssociationImpl;
import org.mobicents.protocols.sctp.netty.NettySctpManagementImpl;

public class SS7FirewallPerformanceTests implements ManagementEventListener, AssociationListener {

    private static final Logger log = Logger.getLogger(SS7FirewallPerformanceTests.class);
    static {
        //configure logging.
        configLog4j();
    }

    public static NettySctpManagementImpl sctpManagement;
    static final private String persistDir = "XmlSS7CLientPerformanceTest";
    private boolean finished = false;
    private boolean sctpClientAssociationUp = false;
    private boolean sctpServerAssociationUp = false;
    NettyAssociationImpl clientAssociation = null;
    int messagesRecieved = 0;
    
    // IN, OUT MAX SCTP STREAMS
    private static Map<Association, Integer> sctpAssciationsMaxInboundStreams = new HashMap<Association, Integer>();
    private static Map<Association, Integer> sctpAssciationsMaxOutboundStreams = new HashMap<Association, Integer>();
    

    private static void configLog4j() {
        InputStream inStreamLog4j = SS7FirewallPerformanceTests.class.getClassLoader().getResourceAsStream("log4j.properties");
        Properties propertiesLog4j = new Properties();
        try {
            propertiesLog4j.load(inStreamLog4j);
            PropertyConfigurator.configure(propertiesLog4j);
        } catch (Exception e) {
            e.printStackTrace();
        }finally
        {
            if(inStreamLog4j!=null)
            {
                try {
                    inStreamLog4j.close();
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }
        log.debug("log4j configured");
    }



    private void initSCTP(IpChannelType ipChannelType) throws Exception {
        log.debug("Initializing SCTP Stack ....");
        //this.sctpManagement = new ManagementImpl(
        //        (String)DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_management_name")
        //);
        this.sctpManagement = new org.mobicents.protocols.sctp.netty.NettySctpManagementImpl(
                (String)"sctp_management"
        );

        this.sctpManagement.setSingleThread(false);

        // TODO no persistent XMLs
        // will cause FileNotFoundException, but currently there is no method to properly disable it
        // If the XMLs are present the SCTP server is started twice and there is problem with reconnections
        this.sctpManagement.setPersistDir(persistDir);

        this.sctpManagement.setOptionSctpInitMaxstreams_MaxInStreams(12);
        this.sctpManagement.setOptionSctpInitMaxstreams_MaxOutStreams(12);

        this.sctpManagement.start();
        this.sctpManagement.setConnectDelay(10000);
        //this.sctpManagement.setMaxIOErrors(30);
        this.sctpManagement.removeAllResourses();
        this.sctpManagement.addManagementEventListener(this);

        // 1. Create SCTP Server     
        this.sctpManagement.addServer(
                (String)"server",
                (String)"127.0.0.1",
                3434,
                ipChannelType,
                true,  //acceptAnonymousConnections
                0,     //maxConcurrentConnectionsCount
                null   //extraHostAddresses
        );


        // 2. FW2 -> Server  Association
        NettyAssociationImpl serverAssociation = (NettyAssociationImpl)this.sctpManagement.addServerAssociation(
                (String)"127.0.0.1",
                2344,
                (String)"server",
                (String)"sctp_from_firewall_to_server",
                ipChannelType
        );
        serverAssociation.setAssociationListener(this);
        this.sctpManagement.startAssociation((String)"sctp_from_firewall_to_server");

        // 3. Client -> FW1 Association
        clientAssociation = (NettyAssociationImpl)this.sctpManagement.addAssociation(
                (String)"127.0.0.1",
                2345,
                (String)"127.0.0.1",
                3433,
                (String)"sctp_from_client_to_firewall",
                ipChannelType,
                null
        );
        clientAssociation.setAssociationListener(this);
        
        // 4. Start Server
        this.sctpManagement.startServer((String)"server");

        log.debug("Initialized SCTP Stack ....");
    }

    /**
     * 
     */
    private void start() {
        try {


            //wait for connection to peer
            while(!(this.sctpClientAssociationUp == true && this.sctpServerAssociationUp == true)) {
                try {
                    if (this.sctpManagement.getAssociation((String)"sctp_from_client_to_firewall").isStarted() == false) {
                        this.sctpManagement.startAssociation((String)"sctp_from_client_to_firewall");
                    }
                    
                    Thread.currentThread().sleep(1000);
                } catch (InterruptedException e) {
                        // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                
                log.info("sctpClientAssociationUp = " + sctpClientAssociationUp);
                log.info("sctpServerAssociationUp = " + sctpServerAssociationUp);
                
            }
            
            int streamNumber;
            int sn = 0;
            byte[] bytes;
            ByteBuffer byteBuffer;
            PayloadData payloadData;
            String a = "sctp_from_client_to_firewall";
             
            
            // ASPUP
            streamNumber = 0;
            bytes = hexStringToByteArray("01000301000000100011000800000002");
            byteBuffer = ByteBuffer.wrap(bytes);
            if (sctpAssciationsMaxInboundStreams.containsKey(a)) {
                sn = streamNumber % sctpAssciationsMaxInboundStreams.get(a).intValue();
            }
            payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, 3, sn);
            clientAssociation.send(payloadData);
            
            // Wait for ASPUP_ACK
            Thread.currentThread().sleep(2000);
            
            // ASPAC
            streamNumber = 0;
            bytes = hexStringToByteArray("0100040100000018000b0008000000020006000800000064");
            byteBuffer = ByteBuffer.wrap(bytes);
            if (sctpAssciationsMaxInboundStreams.containsKey(a)) {
                sn = streamNumber % sctpAssciationsMaxInboundStreams.get(a).intValue();
            }
            payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, 3, sn);
            clientAssociation.send(payloadData);
            
            // Wait
            Thread.currentThread().sleep(2000);

            //do send
            log.info("=== Starting with the performance tests ===");
            
            long startTime = System.nanoTime();
            
            
            int max_messages = 20000;
            for (int i = 0; i < max_messages; i++) {
                
                
                // processUnstructuredSS-Request
                streamNumber = i;
                bytes = hexStringToByteArray("01000101000000b80006000800000064021000a50000000100000002030200010901030e190b12080012042222222222220b12080012041111111111117762754804000000016b432841060700118605010101a036603480020780a109060704000001001302be232821060704000001010101a016a01480099611111111111111f18107961111111111f16c28a12602010002013b301e04010f0410aa582ca65ac562b1582c168bc562b1118007911111111111f1000000");
                byteBuffer = ByteBuffer.wrap(bytes);
                if (sctpAssciationsMaxInboundStreams.containsKey(a)) {
                    sn = streamNumber % sctpAssciationsMaxInboundStreams.get(a).intValue();
                }
                payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, 3, sn);
                clientAssociation.send(payloadData);
               
                if (i%100 == 0) {
                    log.info("Messages sent     ........ #" + i);
                    log.info("Messages recieved ........ #" + messagesRecieved);
                }
                
                // if there is more than 2000 messages sent and not recieved
                // throttle sending to not overflow the recieving buffer
                if (i - messagesRecieved > 2000) {
                    Thread.currentThread().sleep(1000);
                }

            }
            
            
            while (messagesRecieved < max_messages) {
                log.info("=== Wait 1s ===");
                Thread.currentThread().sleep(1000);

                log.info("Messages sent     ........ #" + max_messages);
                log.info("Messages recieved ........ #" + messagesRecieved);
            }
            
            long estimatedTime = System.nanoTime() - startTime;
            log.info("=== Finished with the performance tests ===");
            double t = ((double)(estimatedTime/100000000))/10.0;
            log.info("Time (sec) = " + t );
            log.info("Messages / sec = " + ((double)(max_messages))/t );
            
            

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } 

        this.finished = true;
    }

    /**
     * @return
     */
    private boolean finished() {
        return this.finished;
    }

    public static void main(String[] args) {
        SS7FirewallPerformanceTests ec = new SS7FirewallPerformanceTests();
        try {
            ec.initSCTP(IpChannelType.SCTP);

            ec.start();

            while (!ec.finished()) {
                try {
                    Thread.currentThread().sleep(5000);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }

        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(SS7FirewallPerformanceTests.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    @Override
    public void onServiceStarted() {
        log.debug("[[[[[[[[[[    onServiceStarted      ]]]]]]]]]]");
    }

    @Override
    public void onServiceStopped() {
        log.debug("[[[[[[[[[[    onServiceStopped      ]]]]]]]]]]");
    }

    @Override
    public void onRemoveAllResources() {
        log.debug("[[[[[[[[[[    onRemoveAllResources      ]]]]]]]]]]");
    }

    @Override
    public void onServerAdded(Server server) {
        log.debug("[[[[[[[[[[    onServerAdded      ]]]]]]]]]]");
    }

    @Override
    public void onServerRemoved(Server server) {
        log.debug("[[[[[[[[[[    onServerRemoved      ]]]]]]]]]]");
    }

    @Override
    public void onAssociationAdded(Association asctn) {
        log.debug("[[[[[[[[[[    onAssociationAdded      ]]]]]]]]]]");
    }

    @Override
    public void onAssociationRemoved(Association asctn) {
        log.debug("[[[[[[[[[[    onAssociationRemoved      ]]]]]]]]]]");
    }

    @Override
    public void onAssociationStarted(Association asctn) {
        log.debug("[[[[[[[[[[    onAssociationStarted      ]]]]]]]]]]");
    }

    @Override
    public void onAssociationStopped(Association asctn) {
        log.debug("[[[[[[[[[[    onAssociationStopped      ]]]]]]]]]]");
    }

    @Override
    public void onAssociationUp(Association asctn) {
        log.debug("[[[[[[[[[[    onAssociationUp      ]]]]]]]]]]");
        
        if (asctn.getName().equals("sctp_from_client_to_firewall")) {
            this.sctpClientAssociationUp = true;
        }
        
        if (asctn.getName().equals("sctp_from_firewall_to_server")) {
            this.sctpServerAssociationUp = true;
        }
    }

    @Override
    public void onAssociationDown(Association asctn) {
        log.debug("[[[[[[[[[[    onAssociationDown      ]]]]]]]]]]");
        
        if (asctn.getName().equals("sctp_from_client_to_firewall")) {
            this.sctpClientAssociationUp = false;
        }
        
        if (asctn.getName().equals("sctp_from_firewall_to_server")) {
            this.sctpServerAssociationUp = false;
        }
    }

    @Override
    public void onServerModified(Server server) {
        log.debug("[[[[[[[[[[    onServerModified      ]]]]]]]]]]");
    }

    @Override
    public void onAssociationModified(Association asctn) {
        log.debug("[[[[[[[[[[    onAssociationModified      ]]]]]]]]]]");
    }

    @Override
    public void onCommunicationUp(Association asctn, int maxInboundStreams, int maxOutboundStreams) {
        log.debug("[[[[[[[[[[    onCommunicationUp      ]]]]]]]]]]");
        log.debug("maxInboundStreams = " + maxInboundStreams);
        log.debug("maxOutoundStreams = " + maxOutboundStreams);
        
        sctpAssciationsMaxInboundStreams.put(asctn, maxInboundStreams);
        sctpAssciationsMaxOutboundStreams.put(asctn, maxOutboundStreams);
    }

    @Override
    public void onCommunicationShutdown(Association asctn) {
        log.debug("[[[[[[[[[[    onCommunicationShutdown      ]]]]]]]]]]");
    }

    @Override
    public void onCommunicationLost(Association asctn) {
        log.debug("[[[[[[[[[[    onCommunicationLost      ]]]]]]]]]]");
    }

    @Override
    public void onCommunicationRestart(Association asctn) {
        log.debug("[[[[[[[[[[    onCommunicationRestart      ]]]]]]]]]]");
    }

    @Override
    public void onPayload(Association asctn, PayloadData pd) {
        log.debug("[[[[[[[[[[    onPayload      ]]]]]]]]]]");
        
        if (messagesRecieved == 0) {
            
            // Answer
            try {
                int sn = 0;
                int streamNumber = 0;
                byte[] bytes;
                ByteBuffer byteBuffer;
                PayloadData payloadData;
                
                // ASPUP_ACK
                bytes = hexStringToByteArray("01000304000000100011000800000003");
                byteBuffer = ByteBuffer.wrap(bytes);
                if (sctpAssciationsMaxInboundStreams.containsKey(asctn.getName())) {
                    sn = streamNumber % sctpAssciationsMaxInboundStreams.get(asctn.getName()).intValue();
                }
                payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, 3, sn);
                asctn.send(payloadData);            
            } catch (Exception ex) {
                java.util.logging.Logger.getLogger(SS7FirewallPerformanceTests.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        if (messagesRecieved == 1) {
            
            // Answer
            try {
                int sn = 0;
                int streamNumber = 0;
                byte[] bytes;
                ByteBuffer byteBuffer;
                PayloadData payloadData;

                // ACPAC_ACK
                bytes = hexStringToByteArray("0100040300000018000b0008000000020006000800000064");
                byteBuffer = ByteBuffer.wrap(bytes);
                if (sctpAssciationsMaxInboundStreams.containsKey(asctn.getName())) {
                    sn = streamNumber % sctpAssciationsMaxInboundStreams.get(asctn.getName()).intValue();
                }
                payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, 3, sn);
                asctn.send(payloadData);
                
                Thread.currentThread().sleep(1000);
                
                // NTFY
                bytes = hexStringToByteArray("0100000100000020000d00080001000300110008000000030006000800000064");
                byteBuffer = ByteBuffer.wrap(bytes);
                if (sctpAssciationsMaxInboundStreams.containsKey(asctn.getName())) {
                    sn = streamNumber % sctpAssciationsMaxInboundStreams.get(asctn.getName()).intValue();
                }
                payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, 3, sn);
                asctn.send(payloadData);
                
            } catch (Exception ex) {
                java.util.logging.Logger.getLogger(SS7FirewallPerformanceTests.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        messagesRecieved++;
    }

    @Override
    public void inValidStreamId(PayloadData pd) {
        log.debug("[[[[[[[[[[    inValidStreamId      ]]]]]]]]]]");
    }

}