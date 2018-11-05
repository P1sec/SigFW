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
 * Modified jDiameter ExampleCient.java example
 * 
 * 
 * 
 * 
 * This modules requires DiameterFirewallFirstInstance and DiameterFirewallSecondInstance to be running
 * Or alternatively  DiameterFirewall to be running
 * 
 */
package diameterfw;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.jdiameter.api.Answer;
import org.jdiameter.api.EventListener;
import org.jdiameter.api.Request;
import org.mobicents.protocols.api.Association;
import org.mobicents.protocols.api.AssociationListener;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.api.ManagementEventListener;
import org.mobicents.protocols.api.PayloadData;
import org.mobicents.protocols.api.Server;
import org.mobicents.protocols.sctp.netty.NettyAssociationImpl;
import org.mobicents.protocols.sctp.netty.NettySctpManagementImpl;

public class DiameterFirewallPerformanceTests implements EventListener<Request, Answer>, ManagementEventListener, AssociationListener {

    private static final Logger log = Logger.getLogger(DiameterFirewallPerformanceTests.class);
    static {
        //configure logging.
        configLog4j();
    }

    public static NettySctpManagementImpl sctpManagement;
    static final private String persistDir = "XmlDiameterCLientPerformanceTest";
    private boolean finished = false;
    private boolean sctpClientAssociationUp = false;
    private boolean sctpServerAssociationUp = false;
    NettyAssociationImpl clientAssociation = null;
    int messagesRecieved = 0;
    
    // IN, OUT MAX SCTP STREAMS
    private static Map<Association, Integer> sctpAssciationsMaxInboundStreams = new HashMap<Association, Integer>();
    private static Map<Association, Integer> sctpAssciationsMaxOutboundStreams = new HashMap<Association, Integer>();
    

    private static void configLog4j() {
        InputStream inStreamLog4j = DiameterFirewallPerformanceTests.class.getClassLoader().getResourceAsStream("log4j.properties");
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
                3868,
                ipChannelType,
                true,  //acceptAnonymousConnections
                0,     //maxConcurrentConnectionsCount
                null   //extraHostAddresses
        );


        // 2. FW2 -> Server  Association
        NettyAssociationImpl serverAssociation = (NettyAssociationImpl)this.sctpManagement.addServerAssociation(
                (String)"127.0.0.1",
                13869,
                (String)"server",
                (String)"sctp_from_firewall_to_server",
                ipChannelType
        );
        serverAssociation.setAssociationListener(this);
        this.sctpManagement.startAssociation((String)"sctp_from_firewall_to_server");

        // 3. Client -> FW1 Association
        clientAssociation = (NettyAssociationImpl)this.sctpManagement.addAssociation(
                (String)"127.0.0.1",
                13868,
                (String)"127.0.0.1",
                3869,
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
             
            /*
            // CER
            streamNumber = 0;
            bytes = hexStringToByteArray("010000a0800001010000000062d7a7f75ad0000000000108400000113132372e302e302e31000000000001284000002265786368616e6765436c69656e742e6578616d706c652e6f72670000000001014000000e00017f00000100000000010a4000000c000000000000010d000000116a4469616d65746572000000000001024000000c010000230000010b0000000c00000001000001164000000ce2d7a85d");
            byteBuffer = ByteBuffer.wrap(bytes);
            if (sctpAssciationsMaxInboundStreams.containsKey(a)) {
                sn = streamNumber % sctpAssciationsMaxInboundStreams.get(a).intValue();
            }
            payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, 0, sn);
            clientAssociation.send(payloadData);

            
            // DWR
            streamNumber = 0;
            bytes = hexStringToByteArray("01000058800001180000000062dbde896c10000600000108400000113132372e302e302e31000000000001284000002265786368616e6765436c69656e742e6578616d706c652e6f72670000000001164000000ce2dbdf20");
            byteBuffer = ByteBuffer.wrap(bytes);
            if (sctpAssciationsMaxInboundStreams.containsKey(a)) {
                sn = streamNumber % sctpAssciationsMaxInboundStreams.get(a).intValue();
            }
            payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, 0, sn);
            clientAssociation.send(payloadData);
            */
            
            
            //do send
            log.info("=== Starting with the performance tests ===");
            
            long startTime = System.nanoTime();
            
            
            int max_messages = 20000;
            for (int i = 0; i < max_messages; i++) {
                
                
                // ULR
                streamNumber = i;
                bytes = hexStringToByteArray("010000f88000013c0100002362e31f1209d000020000010740000037426164437573746f6d53657373696f6e49643b596573576543616e5061737349643b3135343134303438333235313400000001024000000c010000230000011b4000001c65786368616e67652e6578616d706c652e6f726700000108400000113132372e302e302e31000000000001284000002265786368616e6765436c69656e742e6578616d706c652e6f7267000000000001400000183131313131313131313131313131313100000760c00000100001046a00000000000007cfc00000230001046a492077616e7420746f20676574203320616e737765727300");
                byteBuffer = ByteBuffer.wrap(bytes);
                if (sctpAssciationsMaxInboundStreams.containsKey(a)) {
                    sn = streamNumber % sctpAssciationsMaxInboundStreams.get(a).intValue();
                }
                payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, 0, sn);
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
        DiameterFirewallPerformanceTests ec = new DiameterFirewallPerformanceTests();
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
            java.util.logging.Logger.getLogger(DiameterFirewallPerformanceTests.class.getName()).log(Level.SEVERE, null, ex);
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
    public void receivedSuccessMessage(Request r, Answer a) {
        log.debug("[[[[[[[[[[    receivedSuccessMessage      ]]]]]]]]]]");
    }

    @Override
    public void timeoutExpired(Request r) {
        log.debug("[[[[[[[[[[    timeoutExpired      ]]]]]]]]]]");
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
        
        messagesRecieved++;
    }

    @Override
    public void inValidStreamId(PayloadData pd) {
        log.debug("[[[[[[[[[[    inValidStreamId      ]]]]]]]]]]");
    }

}