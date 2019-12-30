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
 */
package diameterfw;

import com.p1sec.sigfw.SigFW_interface.CryptoInterface;
import sigfw.common.ExternalFirewallRules;
import sigfw.connectorIDS.ConnectorIDS;
import sigfw.connectorIDS.ConnectorIDSModuleRest;
import sigfw.connectorMThreat.ConnectorMThreat;
import sigfw.connectorMThreat.ConnectorMThreatModuleRest;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.xml.bind.DatatypeConverter;
import net.jodah.expiringmap.ExpiringMap;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.authentication.BasicAuthenticator;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.jdiameter.api.Answer;
import org.jdiameter.api.Avp;
import org.jdiameter.api.AvpDataException;
import org.jdiameter.api.AvpSet;
import org.jdiameter.api.Message;
import org.jdiameter.api.ResultCode;
import org.jdiameter.api.Session;
import org.jdiameter.api.Stack;
import org.jdiameter.client.api.IMessage;
import org.jdiameter.client.api.parser.ParseException;
import org.jdiameter.client.impl.parser.MessageParser;
import org.jdiameter.server.impl.StackImpl;
import org.json.simple.JSONObject;
import org.mobicents.diameter.dictionary.AvpDictionary;
import org.mobicents.diameter.dictionary.AvpRepresentation;
import org.mobicents.protocols.api.Association;
import org.mobicents.protocols.api.AssociationListener;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.api.ManagementEventListener;
import org.mobicents.protocols.api.PayloadData;
import org.mobicents.protocols.api.Server;
import org.mobicents.protocols.api.ServerListener;
import static diameterfw.DiameterFirewallConfig.keyFactoryRSA;
import static diameterfw.DiameterFirewallConfig.keyFactoryEC;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.interfaces.ECPublicKey;
import com.p1sec.sigfw.SigFW_interface.FirewallRulesInterface;
import static diameterfw.DTLSOverDatagram.log;
import static diameterfw.DTLSOverDatagram.printHex;
import java.io.FileInputStream;
import java.net.DatagramPacket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.mobicents.protocols.sctp.netty.NettyAssociationImpl;
import org.mobicents.protocols.sctp.netty.NettySctpManagementImpl;
import sigfw.common.Crypto;
import sigfw.common.Utils;
import sigfw.common.AvpSetImpl;
import sigfw.common.AvpImpl;
import org.mobicents.diameter.dictionary.AvpDictionary;

/**
 * @author Martin Kacer
 * 
 */
public class DiameterFirewall implements ManagementEventListener, ServerListener, AssociationListener {
    private static final Logger logger = Logger.getLogger(DiameterFirewall.class);
    static {
        configLog4j();
    }

    private static void configLog4j() {
        InputStream inStreamLog4j = DiameterFirewall.class.getClassLoader().getResourceAsStream("log4j.properties");
        Properties propertiesLog4j = new Properties();
        try {
            propertiesLog4j.load(inStreamLog4j);
            PropertyConfigurator.configure(propertiesLog4j);
        } catch (Exception e) {
            e.printStackTrace();
        }

        logger.debug("log4j configured");

    }

    private static final String dictionaryFile = "dictionary.xml";
    private AvpDictionary dictionary = AvpDictionary.INSTANCE;
    private Stack stack;

    // Executor Threads
    ExecutorService threadPool = Executors.newFixedThreadPool(16);

    // ////////////////////////////////////////
    // Objects which will be used in action //
    // ////////////////////////////////////////
    private Session session;
    private int toReceiveIndex = 0;
    private boolean finished = false;

    // Unit Tests flags
    public static boolean unitTesting = false;
    public static boolean unitTestingFlags_sendDiameterMessage = false;
    public static int unitTestingFlags_sendDiameterMessage_resultCode = ResultCode.SUCCESS;

    // SCTP
    public static NettySctpManagementImpl sctpManagement;
    public static List<Association> anonymousAssociations = new ArrayList<Association>();
    
    // IN, OUT MAX SCTP STREAMS
    private static Map<Association, Integer> sctpAssciationsMaxInboundStreams = new HashMap<Association, Integer>();
    private static Map<Association, Integer> sctpAssciationsMaxOutboundStreams = new HashMap<Association, Integer>();
    
    // Diameter
    public static final MessageParser parser = new MessageParser();
    
    static private String configName = "diameterfw.json";

    // API
    private static org.eclipse.jetty.server.Server jettyServer;
    
    // IDS API
    private static ConnectorIDS connectorIDS = null;
    
    // mThreat API
    static ConcurrentLinkedDeque<String> mThreat_alerts = new ConcurrentLinkedDeque<String>();
    private static ConnectorMThreat connectorMThreat = null;
    
    // Externel Firewall Rules Interface
    FirewallRulesInterface externalFirewallRules = new ExternalFirewallRules();
    
    // Crypto Module
    CryptoInterface crypto = new Crypto();
    
    // Honeypot Diameter address NAT
    // Session Key: Origin_Host:Origin_Realm (from Request)
    // Value: Dest_Host : Dest_Realm
    private static Map<String, String> dnat_sessions = null;
    
    // Encryption Autodiscovery
    // Key: E2E ID
    // Value: Dest_Realm
    private static Map<Long, String> encryption_autodiscovery_sessions = ExpiringMap.builder()
                                                .expiration(60, TimeUnit.SECONDS)
                                                .build();
    // Encryption Autodiscovery Reverse
    // Value: Dest_Realm
    // Key: E2E ID
    private static Map<String, Long> encryption_autodiscovery_sessions_reverse = ExpiringMap.builder()
                                                .expiration(60, TimeUnit.SECONDS)
                                                .build();
    
    // DTLS Session
    // Key: E2E ID
    // Value: Dest_Realm
    //private static Map<Long, String> dtls_sessions = ExpiringMap.builder()
    //                                            .expiration(60, TimeUnit.SECONDS)
    //                                            .build();
    
    public static KeyManagerFactory kmf = null;
    
    private static int DTLS_BUFFER_SIZE = 64*1024;
    private static int DTLS_MAX_HANDSHAKE_LOOPS = 200;
    private static int DTLS_MAXIMUM_PACKET_SIZE = 10*1024;
    private static int DTLS_SOCKET_TIMEOUT = 5 * 1000; // in millis
    private static int DTLS_SOCKET_THREAD_SLEEP = 100; // in millis
    private static int DTLS_MAX_SESSION_DURATION = 60*60; // in seconds, after the new handshake is required
    private static int DTLS_MAX_HANDSHAKE_DURATION = 10; // in seconds, after the handshake SSL engine is dropped. Has to be shorter than half of DTLS_MAX_SESSION_DURATION
    //private static Exception dtls_clientException = null;
    //private static Exception dtls_serverException = null;
    private static String dtls_pathToStores = "./";
    private static String dtls_keyStoreFile = "keystore";
    private static String dtls_trustStoreFile = "truststore";
    private static String dtls_passwd = "keystore";
    public static String dtls_keyStoreAlias = "keystore";
    private static String dtls_keyFilename =
            System.getProperty("test.src", ".") + "/" + dtls_pathToStores +
                "/" + dtls_keyStoreFile;
    private static String dtls_trustFilename =
            System.getProperty("test.src", ".") + "/" + dtls_pathToStores +
                "/" + dtls_trustStoreFile;
    
    // protectedAVPs codes used for DTLS encryption
    List<Integer> protectedAVPCodes = new ArrayList<Integer>(Arrays.asList(
            1,  // User-Name AVP
            1600  // MME-Location-Information
    ));

            
    
    // SSL engines stored for peers used by DTLS
    // this expiring, used to trigger new handshakes after they expire
    private static Map<String, SSLEngine> dtls_engine_expiring_server = ExpiringMap.builder()
                                                .expiration(DTLS_MAX_SESSION_DURATION, TimeUnit.SECONDS)
                                                .build(); // <peer_realm, SSLEngine> 
    private static Map<String, SSLEngine> dtls_engine_expiring_client = ExpiringMap.builder()
                                                .expiration(DTLS_MAX_SESSION_DURATION, TimeUnit.SECONDS)
                                                .build(); // <peer_realm, SSLEngine> 
    // SSL engines stored for peers used by DTLS
    // this is permanent, used for actual encryption
    // 2 DTLS sessions, in and out. Server side is used for decrypt, client side for encrypt.
    private static Map<String, SSLEngine> dtls_engine_permanent_server = new ConcurrentHashMap<>(); // <peer_realm, SSLEngine>
    private static Map<String, SSLEngine> dtls_engine_permanent_client = new ConcurrentHashMap<>(); // <peer_realm, SSLEngine>
    // DTLS SSL engines being handshaked
    private static Map<String, SSLEngine> dtls_engine_handshaking_server = ExpiringMap.builder()
                                                .expiration(DTLS_MAX_HANDSHAKE_DURATION, TimeUnit.SECONDS)
                                                .build(); // <peer_realm, SSLEngine>
    // DTLS SSL engines being handshaked
    private static Map<String, SSLEngine> dtls_engine_handshaking_client = ExpiringMap.builder()
                                                .expiration(DTLS_MAX_HANDSHAKE_DURATION, TimeUnit.SECONDS)
                                                .build(); // <peer_realm, SSLEngine> 
    // DTLS handshake thread running indicator
    //private static Map<String, Thread> dtls_handshake_treads = ExpiringMap.builder()
    //                                            .expiration(DTLS_MAX_HANDSHAKE_DURATION, TimeUnit.SECONDS)
    //                                            .build(); // <peer_realm, Thread> 
    
    // DTLS client initialization timer, do not initiate new DTLS handshake till this timer
    // Value: Dest_Realm
    // Key: E2E ID
    private static Map<String, Long> dtls_handshake_timer = ExpiringMap.builder()
                                                .expiration(DTLS_MAX_HANDSHAKE_DURATION*2, TimeUnit.SECONDS)
                                                .build();
    
    
    private static Map<String, ConcurrentLinkedQueue<DatagramOverDiameterPacket>> datagramOverDiameterSocket_inbound_server = ExpiringMap.builder()
                                                .expiration(DTLS_MAX_HANDSHAKE_DURATION, TimeUnit.SECONDS)
                                                .build(); // <peer_realm, SSLEngine> //new ConcurrentHashMap<>(); //new ConcurrentLinkedQueue<>();
    private static Map<String, ConcurrentLinkedQueue<DatagramOverDiameterPacket>> datagramOverDiameterSocket_inbound_client = ExpiringMap.builder()
                                                .expiration(DTLS_MAX_HANDSHAKE_DURATION, TimeUnit.SECONDS)
                                                .build(); // <peer_realm, SSLEngine> //new ConcurrentHashMap<>(); //new ConcurrentLinkedQueue<>();
    //private static ConcurrentLinkedQueue<DatagramOverDiameterPacket> datagramOverDiameterSocket_outbound = new ConcurrentLinkedQueue<>();
    
    
    
    // Diameter sessions
    // TODO consider additng Diameter Host into Key
    // Used to correlate Diameter Answers with Requests, to learn the Dest-Realm for the answer
    // Key: AppID + ":" + "CommandCode" + ":" + Dest_realm + ":" + msg.getEndToEndIdentifier()
    // Value: Origin-Realm from first message detected (Request)
    public static Map<String, String> diameter_sessions = ExpiringMap.builder()
                                                .expiration(10, TimeUnit.SECONDS)
                                                .build();
    
    // Encryption Autodiscovery
    // TODO
    
    static Random randomGenerator = new Random();

    static final private String persistDir = "XmlDiameterFirewall";
    
    // proprietary autodiscovery used for asymmetric encryption
    // not according to IANA and GSMA FS.19
    static final private int CC_AUTO_ENCRYPTION = 999;
    static final private int AVP_AUTO_ENCRYPTION_CAPABILITIES = 1101;
    static final private int AVP_AUTO_ENCRYPTION_REALM = 1102;
    static final private int AVP_AUTO_ENCRYPTION_PUBLIC_KEY = 1103;
    static final private int AVP_AUTO_ENCRYPTION_PUBLIC_KEY_TYPE = 1104;
    //
    
    // Command Code for DatagramOverDiameterPacket 
    static final private int AI_DESS_INTERFACE = 16777360;
    static final public int VENDOR_ID = 46304;
    static final private int CC_DTLS_HANDSHAKE_CLIENT = 8388737;     // DTLS handshake messages
    static final private int CC_DTLS_HANDSHAKE_SERVER = 8388738;     // DTLS handshake messages
    static final private int AVP_DESS_ENCRYPTED = 2000;
    static final private int AVP_DESS_DTLS_DATA = 2001;  
    
    /**
     * Reset Unit Testing Flags
     */
    public void resetUnitTestingFlags() {
        unitTestingFlags_sendDiameterMessage = false;
        unitTestingFlags_sendDiameterMessage_resultCode = ResultCode.SUCCESS;
    }
    
    private void initSCTP(IpChannelType ipChannelType) throws Exception {
        logger.debug("Initializing SCTP Stack ....");
        //this.sctpManagement = new ManagementImpl(
        //        (String)DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_management_name")
        //);
        this.sctpManagement = new org.mobicents.protocols.sctp.netty.NettySctpManagementImpl(
                (String)DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_management_name")
        );
        
        this.sctpManagement.setSingleThread(true);

        // TODO no persistent XMLs
        // will cause FileNotFoundException, but currently there is no method to properly disable it
        // If the XMLs are present the SCTP server is started twice and there is problem with reconnections
        this.sctpManagement.setPersistDir(persistDir);

        this.sctpManagement.setOptionSctpInitMaxstreams_MaxInStreams(Integer.parseInt((String)DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_max_in_streams")));
        this.sctpManagement.setOptionSctpInitMaxstreams_MaxOutStreams(Integer.parseInt((String)DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_max_out_streams")));
        
        this.sctpManagement.start();
        this.sctpManagement.setConnectDelay(10000);
        //this.sctpManagement.setMaxIOErrors(30);
        this.sctpManagement.removeAllResourses();
        this.sctpManagement.addManagementEventListener(this);
        this.sctpManagement.setServerListener(this);
        
        
        // 1. Create SCTP Server     
        List<Map<String, Object>> sctp_server = DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_server");
        for (int i = 0; i < sctp_server.size(); i++) {
        
            String acceptAnonymousAssociations = (String)sctp_server.get(i).get("accept_anonymous_associations");
                    
            if(acceptAnonymousAssociations != null && acceptAnonymousAssociations.equals("true")) {
                this.sctpManagement.addServer(
                        (String)sctp_server.get(i).get("server_name"),
                        (String)sctp_server.get(i).get("host_address"),
                        Integer.parseInt((String)sctp_server.get(i).get("port")),
                        ipChannelType,
                        true,  //acceptAnonymousConnections
                        0,     //maxConcurrentConnectionsCount
                        null   //extraHostAddresses
                );
            } else {
                this.sctpManagement.addServer(
                        (String)sctp_server.get(i).get("server_name"),
                        (String)sctp_server.get(i).get("host_address"),
                        Integer.parseInt((String)sctp_server.get(i).get("port")),
                        ipChannelType, null
                );
            }
        }

        // 2. Create Client <-> FW Association
        List<Map<String, Object>> sctp_server_association = DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_server_association");
        for (int i = 0; i < sctp_server_association.size(); i++) {
            NettyAssociationImpl serverAssociation = (NettyAssociationImpl)this.sctpManagement.addServerAssociation(
                    (String)sctp_server_association.get(i).get("peer_address"),
                    Integer.parseInt((String)sctp_server_association.get(i).get("peer_port")),
                    (String)sctp_server_association.get(i).get("server_name"),
                    (String)sctp_server_association.get(i).get("assoc_name"),
                    ipChannelType
            );
            serverAssociation.setAssociationListener(this);
            this.sctpManagement.startAssociation((String)sctp_server_association.get(i).get("assoc_name"));
        }


        // 3. Create FW <-> Server Association
        List<Map<String, Object>> sctp_association = DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_association");
        for (int i = 0; i < sctp_association.size(); i++) {
            NettyAssociationImpl clientAssociation = (NettyAssociationImpl)this.sctpManagement.addAssociation(
                    (String)sctp_association.get(i).get("host_address"),
                    Integer.parseInt((String)sctp_association.get(i).get("host_port")),
                    (String)sctp_association.get(i).get("peer_address"),
                    Integer.parseInt((String)sctp_association.get(i).get("peer_port")),
                    (String)sctp_association.get(i).get("assoc_name"),
                    ipChannelType,
                    null
            );
            clientAssociation.setAssociationListener(this);
            this.sctpManagement.startAssociation((String)sctp_association.get(i).get("assoc_name"));
        }

        // 4. Start Server
        for (int i = 0; i < sctp_server.size(); i++) {
            this.sctpManagement.startServer(
                    (String)sctp_server.get(i).get("server_name")
            );
        }

        logger.debug("Initialized SCTP Stack ....");
    }

    public void initStack(IpChannelType ipChannelType) throws Exception {
        
        // Initialize SigFW Extensions
        try {
            logger.info("Trying to load SigFW extensions from: " + "file://" + System.getProperty("user.dir")  + "/src/main/resources/SigFW_extension-1.0.jar");
            
            // Constructing a URL form the path to JAR
            URL u = new URL("file://" + System.getProperty("user.dir")  + "/src/main/resources/SigFW_extension-1.0.jar");
            
            // Creating an instance of URLClassloader using the above URL and parent classloader 
            ClassLoader loader  = URLClassLoader.newInstance(new URL[]{u}, ExternalFirewallRules.class.getClassLoader());

            // Returns the class object
            Class<?> mainClassRules = Class.forName("com.p1sec.sigfw.SigFW_extension.rules.ExtendedFirewallRules", true, loader);
            externalFirewallRules = (FirewallRulesInterface) mainClassRules.getDeclaredConstructor().newInstance();

            // Returns the class object
            Class<?> mainClassCrypto = Class.forName("com.p1sec.sigfw.SigFW_extension.crypto.ExtendedCrypto", true, loader);
            crypto = (CryptoInterface) mainClassCrypto.getDeclaredConstructor().newInstance();

            
            logger.info("Sucessfully loaded SigFW extensions ....");
        
        } catch (Exception e) {
            logger.info("Failed to load SigFW extensions: " + e.toString());
        }
        // End of SigFW Extensions
        
        if (logger.isInfoEnabled()) {
                logger.info("Initializing Stack...");
        }
        
        this.initSCTP(ipChannelType);
        

        InputStream is = null;
        try {
            dictionary.parseDictionary(this.getClass().getClassLoader().getResourceAsStream(dictionaryFile));
            logger.info("AVP Dictionary successfully parsed.");
            this.stack = new StackImpl();

            /*is = this.getClass().getClassLoader().getResourceAsStream(configFile);

            Configuration config = new XMLConfiguration(is);
            factory = stack.init(config);
            if (logger.isInfoEnabled()) {
                logger.info("Stack Configuration successfully loaded.");
            }*/

            /*Set<org.jdiameter.api.ApplicationId> appIds = stack.getMetaData().getLocalPeer().getCommonApplications();

            logger.info("Diameter Stack  :: Supporting " + appIds.size() + " applications.");
            for (org.jdiameter.api.ApplicationId x : appIds) {
                logger.info("Diameter Stack  :: Common :: " + x);
            }
            //is.close();
            Network network = stack.unwrap(Network.class);
            network.addNetworkReqListener(this, this.authAppId);*/
        } catch (Exception e) {
            e.printStackTrace();
            if (this.stack != null) {
                this.stack.destroy();
            }

            if (is != null) {
                try {
                    is.close();
                } catch (IOException e1) {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }
            }
            return;
        }

    }

    private void dumpMessage(Message message, boolean sending) {
        if (logger.isInfoEnabled()) {
            logger.info((sending?"Sending ":"Received ") + (message.isRequest() ? "Request: " : "Answer: ") + message.getCommandCode() + "\nE2E:"
                + message.getEndToEndIdentifier() + "\nHBH:" + message.getHopByHopIdentifier() + "\nAppID:" + message.getApplicationId());
            logger.info("AVPS["+message.getAvps().size()+"]: \n");
            try {
                printAvps(message.getAvps());
            } catch (AvpDataException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }

    private void printAvps(AvpSet avpSet) throws AvpDataException {
        printAvpsAux(avpSet, 0);
    }

    /**
     * Prints the AVPs present in an AvpSet with a specified 'tab' level
     * 
     * @param avpSet
     *            the AvpSet containing the AVPs to be printed
     * @param level
     *            an int representing the number of 'tabs' to make a pretty
     *            print
     * @throws AvpDataException
     */
    private void printAvpsAux(AvpSet avpSet, int level) throws AvpDataException {
        String prefix = "                      ".substring(0, level * 2);

        for (Avp avp : avpSet) {
            AvpRepresentation avpRep = AvpDictionary.INSTANCE.getAvp(avp.getCode(), avp.getVendorId());

            if (avpRep != null && avpRep.getType().equals("Grouped")) {
                logger.info(prefix + "<avp name=\"" + avpRep.getName() + "\" code=\"" + avp.getCode() + "\" vendor=\"" + avp.getVendorId() + "\">");
                printAvpsAux(avp.getGrouped(), level + 1);
                logger.info(prefix + "</avp>");
            } else if (avpRep != null) {
                String value = "";

                if (avpRep.getType().equals("Integer32"))
                    value = String.valueOf(avp.getInteger32());
                else if (avpRep.getType().equals("Integer64") || avpRep.getType().equals("Unsigned64"))
                    value = String.valueOf(avp.getInteger64());
                else if (avpRep.getType().equals("Unsigned32"))
                    value = String.valueOf(avp.getUnsigned32());
                else if (avpRep.getType().equals("Float32"))
                    value = String.valueOf(avp.getFloat32());
                else
                    //value = avp.getOctetString();
                    value = new String(avp.getOctetString(), StandardCharsets.UTF_8);

                logger.info(prefix + "<avp name=\"" + avpRep.getName() + "\" code=\"" + avp.getCode() + "\" vendor=\"" + avp.getVendorId()
                    + "\" value=\"" + value + "\" />");
            }
        }
    }


    /**
     * @return
     */
    private boolean finished() {
        return this.finished;
    }

    public static void main(String[] args) {

        // clear XML dir
        File index = new File(persistDir);
        if (!index.exists()) {
            index.mkdir();
        } else {
            String[]entries = index.list();
            for(String s: entries){
                File currentFile = new File(index.getPath(),s);
                currentFile.delete();
            }
        }
        //
        
        //
        if (args.length >= 1) {
            configName = args[0];
        }

        try {
            // Use last config if available
            DiameterFirewallConfig.loadConfigFromFile(configName + ".last");
            // TODO use the following directive instead to do not use .last configs
            //DiameterFirewallConfig.loadConfigFromFile(configName);
        } catch (Exception ex) {
            try {
                DiameterFirewallConfig.loadConfigFromFile(configName);
            } catch (IOException ex1) {
                java.util.logging.Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex1);
            } catch (org.json.simple.parser.ParseException ex1) {
                java.util.logging.Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex1);
            }
        }
        
        if (DiameterFirewallConfig.firewallPolicy == DiameterFirewallConfig.FirewallPolicy.DNAT_TO_HONEYPOT) {
            
            
            dnat_sessions = ExpiringMap.builder()
                                                .expiration(DiameterFirewallConfig.honeypot_dnat_session_expiration_timeout, TimeUnit.SECONDS)
                                                .build();
        }
        
        
        //logger.setLevel(org.apache.log4j.Level.DEBUG);

        // ---- REST API -----
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");

        jettyServer = new org.eclipse.jetty.server.Server();

        HttpConfiguration http_config = new HttpConfiguration();
        http_config.setSecureScheme("https");
        http_config.setSecurePort(8443);
        http_config.setOutputBufferSize(32768);
        /*ServerConnector http = new ServerConnector(jettyServer,
                new HttpConnectionFactory(http_config));
        http.setPort(8080);
        http.setIdleTimeout(30000);*/

        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setIncludeCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        sslContextFactory.setIncludeProtocols("TLSv1.2");
        //sslContextFactory.setKeyStorePath(keystoreFile.getAbsolutePath());
        //sslContextFactory.setKeyStorePassword("OBF:1vny1zlo1x8e1vnw1vn61x8g1zlu1vn4");
        //sslContextFactory.setKeyManagerPassword("OBF:1u2u1wml1z7s1z7a1wnl1u2g");
        sslContextFactory.setKeyStorePath("diameterfw_keystore");
        sslContextFactory.setKeyStorePassword("BkgcNSrVn4wQWNpEowoHeHxgZeSn5WV7");
        sslContextFactory.setKeyManagerPassword("BkgcNSrVn4wQWNpEowoHeHxgZeSn5WV7");


        HttpConfiguration https_config = new HttpConfiguration(http_config);
        SecureRequestCustomizer src = new SecureRequestCustomizer();
        src.setStsMaxAge(2000);
        src.setStsIncludeSubDomains(true);
        https_config.addCustomizer(src);

        ServerConnector https = new ServerConnector(jettyServer,
            new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                new HttpConnectionFactory(https_config));
        https.setPort(8443);
        https.setIdleTimeout(500000);

        //jettyServer.setConnectors(new Connector[] { http, https });
        jettyServer.setConnectors(new Connector[] { https });



        // ------- Basic Auth ---------

        LoginService loginService = new HashLoginService("diameterfw",
                "realm.properties");
        jettyServer.addBean(loginService);

        ConstraintSecurityHandler security = new ConstraintSecurityHandler();
        jettyServer.setHandler(security);

        Constraint constraint = new Constraint();
        constraint.setName("auth");
        constraint.setAuthenticate(true);
        constraint.setRoles(new String[] { "user", "admin" });

        ConstraintMapping mapping = new ConstraintMapping();
        mapping.setPathSpec("/*");
        mapping.setConstraint(constraint);

        security.setConstraintMappings(Collections.singletonList(mapping));
        security.setAuthenticator(new BasicAuthenticator());
        security.setLoginService(loginService);

        security.setHandler(context);
        // --------------------------       

        //jettyServer.setHandler(context);

        ServletHolder jerseyServlet = context.addServlet(
             org.glassfish.jersey.servlet.ServletContainer.class, "/*");
        jerseyServlet.setInitOrder(0);

        // Tells the Jersey Servlet which REST service/class to load.
        jerseyServlet.setInitParameter(
           "jersey.config.server.provider.classnames",
           DiameterFirewallAPI_V1_0.class.getCanonicalName());


        try {
            jettyServer.start();
            //jettyServer.join();
        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            //jettyServer.destroy();
        }
        // ------------------
        
        // ---- IDS API -----
        try {
            String ids_api_type = (String)DiameterFirewallConfig.get("$.sigfw_configuration.firewall_rules.ids.ids_api_type");
            if(ids_api_type != null && ids_api_type.equals("REST")) {
                connectorIDS = new ConnectorIDS();
                connectorIDS.initialize(ConnectorIDSModuleRest.class);

                List<Map<String, Object>> ids_servers = DiameterFirewallConfig.get("$.sigfw_configuration.firewall_rules.ids.ids_servers");
                for (int i = 0; i < ids_servers.size(); i++) {
                    //connectorIDS.addServer("https://localhost:8443", "user", "password");
                    connectorIDS.addServer(
                            (String)ids_servers.get(i).get("host"),
                            (String)ids_servers.get(i).get("username"),
                            (String)ids_servers.get(i).get("password")
                    );

                    // TODO remove this code, used only for to test REST API
                    // System.out.println("--------------------------");
                    // System.out.println(connectorIDS.evalSCCPMessage("test"));
                    // System.out.println("--------------------------");
                    // ------------------
                }
            }
        } catch (Exception e) {
            // None
        }
        
        // ---- mThreat API -----
        try {
            String mthreat_api_type = (String)DiameterFirewallConfig.get("$.sigfw_configuration.firewall_rules.mthreat.mthreat_api_type");
            if(mthreat_api_type != null && mthreat_api_type.equals("REST")) {
                connectorMThreat = new ConnectorMThreat();
                connectorMThreat.initialize(ConnectorMThreatModuleRest.class, mThreat_alerts);

                List<Map<String, Object>> ids_servers = DiameterFirewallConfig.get("$.sigfw_configuration.firewall_rules.mthreat.mthreat_servers");
                for (int i = 0; i < ids_servers.size(); i++) {
                    //connectorIDS.addServer("https://localhost:8443", "user", "password");
                    connectorMThreat.addServer(
                            (String)ids_servers.get(i).get("host"),
                            (String)ids_servers.get(i).get("username"),
                            (String)ids_servers.get(i).get("password")
                    );
                }
            }
        } catch (Exception e) {
            // None
        }

        IpChannelType ipChannelType = IpChannelType.SCTP;
        if (args.length >= 1 && args[0].toLowerCase().equals("tcp")) {
            ipChannelType = IpChannelType.TCP;
        }

        DiameterFirewall sigfw = new DiameterFirewall();
        try {
            sigfw.initStack(ipChannelType);
        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
        }

        int t = 0;
        while (!sigfw.finished()) {
            try {
                Thread.currentThread().sleep(1000);
                
                t++;
                // Save config every 10s
                if (t%10 == 0) {
                    //logger.debug("X");
                    DiameterFirewallConfig.saveConfigToFile(configName + ".last");
                }
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (FileNotFoundException ex) {
                java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    /**
     * Method to send Diameter data message.
     * 
     * @param origin_asctn Origin SCTP association which received the message
     * @param payloadProtocolId SCTP payload id
     * @param streamNumber SCTP stream number
     * @param message Diameter message to be send
     * @param forward_indicator indicator if the message should be forwarded or send back
     * @param lua_hm the LUA parameters, decoded from the message
     */
    private void sendDiameterMessage(Association origin_asctn, int payloadProtocolId, int streamNumber, Message message, boolean forward_indicator, HashMap<String, String> lua_hm) {
        if (this.unitTesting == true) {
            this.unitTestingFlags_sendDiameterMessage = true;
            if (!message.isRequest()) {
                this.unitTestingFlags_sendDiameterMessage_resultCode = ((Answer)message).getResultCode().getCode();
            }
            return;
        }
        
        try {
            
            if (lua_hm != null) {
                if (DiameterFirewallConfig.firewallPolicy == DiameterFirewallConfig.FirewallPolicy.DNAT_TO_HONEYPOT &&  dnat_sessions != null) {
                    // Reverse NAT from Honeypot (the backward messages)
                    if(message.getAvps() != null
                        && ((message.getAvps().getAvp(Avp.ORIGIN_HOST) != null)
                        || (message.getAvps().getAvp(Avp.ORIGIN_REALM) != null) 
                        && (message.getAvps().getAvp(Avp.DESTINATION_HOST) != null
                        || (message.getAvps().getAvp(Avp.DESTINATION_REALM) != null)))
                        && (message.getAvps().getAvp(Avp.ORIGIN_REALM).getAddress().toString().equals(DiameterFirewallConfig.honeypot_diameter_realm))
                        && (message.getAvps().getAvp(Avp.ORIGIN_HOST).getAddress().toString().equals(DiameterFirewallConfig.honeypot_diameter_host))
                        && dnat_sessions.containsKey(lua_hm.get("diameter_dest_host") + ":" + lua_hm.get("diameter_dest_realm"))
                        ) {
                            String original_diameter_host_realm = dnat_sessions.get(dnat_sessions.containsKey(lua_hm.get("diameter_dest_host") + ":" + lua_hm.get("diameter_dest_realm")));   // column delimited
                            String[] host_realm = original_diameter_host_realm.split(":");

                            message.getAvps().removeAvp(Avp.ORIGIN_REALM);
                            message.getAvps().removeAvp(Avp.ORIGIN_HOST);
                            // TODO usa raw AVP encoding, because aaa:// is added by jDiameter
                            //try {
                            message.getAvps().addAvp(Avp.ORIGIN_REALM, host_realm[1], true, false, true);
                            message.getAvps().addAvp(Avp.ORIGIN_HOST, host_realm[0], true, false, true);
                            /*} catch (URISyntaxException ex) {
                                java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (UnknownServiceException ex) {
                                java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                            }*/
                    }
                    // Forward NAT towards Honeypot (for latter forward messages not detected as alerts)
                    if(message.getAvps() != null
                        && ((message.getAvps().getAvp(Avp.ORIGIN_HOST) != null)
                        || (message.getAvps().getAvp(Avp.ORIGIN_REALM) != null) 
                        && (message.getAvps().getAvp(Avp.DESTINATION_HOST) != null
                        || (message.getAvps().getAvp(Avp.DESTINATION_REALM) != null)))
                       && dnat_sessions.containsKey(lua_hm.get("diameter_orig_host") + ":" + lua_hm.get("diameter_orig_realm"))) {

                        message.getAvps().removeAvp(Avp.DESTINATION_REALM);
                        message.getAvps().removeAvp(Avp.DESTINATION_HOST);
                        // TODO usa raw AVP encoding, because aaa:// is added by jDiameter
                        //try {
                        message.getAvps().addAvp(Avp.DESTINATION_REALM, DiameterFirewallConfig.honeypot_diameter_realm, true, false, true);
                        message.getAvps().addAvp(Avp.DESTINATION_HOST, DiameterFirewallConfig.honeypot_diameter_host, true, false, true);
                        /*} catch (URISyntaxException ex) {
                            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (UnknownServiceException ex) {
                            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                        }*/

                    }
                }
            }
            
            List<Map<String, Object>> sctp_server_association = DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_server_association");
            List<Map<String, Object>> sctp_association = DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_association");


            ByteBuffer byteBuffer;
            byteBuffer = parser.encodeMessage((IMessage)message);
        
            int sn = streamNumber;
            
            // FW Server associations (Client -> FW)
            for (int i = 0; i < sctp_server_association.size(); i++) {
                // The anonymous association does not have name, but can be configured in FW config as server association. Therefor run this code also without association name.
                if (origin_asctn.getName() == null || origin_asctn.getName().equals((String)sctp_server_association.get(i).get("assoc_name"))) {
                    try {
                        // TODO round robin
                        if (forward_indicator) {
                            
                            Association a = this.sctpManagement.getAssociation((String)sctp_association.get(0).get("assoc_name"));
                            
                            // crop the outbound stream number to max for given association
                            if (sctpAssciationsMaxInboundStreams.containsKey(a)) {
                                sn = streamNumber % sctpAssciationsMaxInboundStreams.get(a).intValue();
                            }
                            PayloadData payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, payloadProtocolId, sn);
                            
                            a.send(payloadData);
                        } else {
                            // try to use anonymous associations first
                            if (!this.anonymousAssociations.isEmpty()) {
                                
                                Association a = this.anonymousAssociations.get(0);
                                
                                // crop the outbound stream number to max for given association
                                if (sctpAssciationsMaxInboundStreams.containsKey(a)) {
                                    sn = streamNumber % sctpAssciationsMaxInboundStreams.get(a).intValue();
                                }
                                PayloadData payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, payloadProtocolId, sn);
                                
                                a.send(payloadData);
                            } else {
                                
                                Association a = this.sctpManagement.getAssociation((String)sctp_server_association.get(0).get("assoc_name"));
                                
                                // crop the outbound stream number to max for given association
                                if (sctpAssciationsMaxInboundStreams.containsKey(a)) {
                                    sn = streamNumber % sctpAssciationsMaxInboundStreams.get(a).intValue();
                                }
                                PayloadData payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, payloadProtocolId, sn);
                                
                                a.send(payloadData);
                            }
                        }
                    } catch (Exception ex) {
                        java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
                
            }
            // FW Client associations (Server -> FW)
            for (int i = 0; i < sctp_association.size(); i++) {
                // all associations from Server -> FW should have names 
                if (origin_asctn.getName() != null && origin_asctn.getName().equals((String)sctp_association.get(i).get("assoc_name"))) {
                    try {
                        // TODO round robin
                        if (forward_indicator) {
                            // try to use anonymous associations first
                            if (!this.anonymousAssociations.isEmpty()) {
                                
                                Association a = this.anonymousAssociations.get(0);
                                
                                // crop the outbound stream number to max for given association
                                if (sctpAssciationsMaxOutboundStreams.containsKey(a)) {
                                    sn = streamNumber % sctpAssciationsMaxOutboundStreams.get(a).intValue();
                                }
                                PayloadData payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, payloadProtocolId, sn);
                                
                                a.send(payloadData);
                            } else {
                                
                                Association a = this.sctpManagement.getAssociation((String)sctp_server_association.get(0).get("assoc_name"));
                                
                                // crop the outbound stream number to max for given association
                                if (sctpAssciationsMaxOutboundStreams.containsKey(a)) {
                                    sn = streamNumber % sctpAssciationsMaxOutboundStreams.get(a).intValue();
                                }
                                PayloadData payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, payloadProtocolId, sn);
                                
                                a.send(payloadData);
                            }
                        } else {
                            
                            Association a = this.sctpManagement.getAssociation((String)sctp_association.get(0).get("assoc_name"));
                            
                            // crop the outbound stream number to max for given association
                            if (sctpAssciationsMaxOutboundStreams.containsKey(a)) {
                                sn = streamNumber % sctpAssciationsMaxOutboundStreams.get(a).intValue();
                            }
                            PayloadData payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, payloadProtocolId, sn);
                            
                            a.send(payloadData);
                        }
                    } catch (Exception ex) {
                        java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
            this.sctpManagement.getServers().get(0).getAssociations();
        
        } catch (ParseException ex) {
            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
        } catch (AvpDataException ex) {
            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Method to execute firewall policy on target Diameter message.
     * 
     * @param origin_asctn Origin SCTP association which received the message
     * @param payloadProtocolId SCTP payload id
     * @param streamNumber SCTP stream number
     * @param message Original Diameter message
     * @param reason the reason of discarding the message
     * @param lua_hm the LUA parameters, decoded from the message
     */
    private void firewallMessage(Association origin_asctn, int payloadProtocolId, int streamNumber, Message message, String reason, HashMap<String, String> lua_hm) {
        String firewallPolicy = "";
        if (DiameterFirewallConfig.firewallPolicy == DiameterFirewallConfig.FirewallPolicy.DROP_SILENTLY) {
            firewallPolicy = "DROP_SILENTLY";
        } else if (DiameterFirewallConfig.firewallPolicy == DiameterFirewallConfig.FirewallPolicy.DROP_WITH_DIAMETER_ERROR) {
            firewallPolicy = "DROP_WITH_DIAMETER_ERROR";
            
            Answer answer = ((IMessage)(message)).createAnswer(ResultCode.UNABLE_TO_DELIVER);
            if (message.getAvps().getAvp(Avp.DESTINATION_HOST) != null) {
                answer.getAvps().addAvp(Avp.ORIGIN_HOST, message.getAvps().getAvp(Avp.DESTINATION_HOST).getRawData());
            }
            if (message.getAvps().getAvp(Avp.DESTINATION_REALM) != null) {
                answer.getAvps().addAvp(Avp.ORIGIN_REALM, message.getAvps().getAvp(Avp.DESTINATION_REALM).getRawData());
            }
            sendDiameterMessage(origin_asctn, payloadProtocolId, streamNumber, answer, false, lua_hm);
        } else if (DiameterFirewallConfig.firewallPolicy == DiameterFirewallConfig.FirewallPolicy.DNAT_TO_HONEYPOT && dnat_sessions != null
                && message.getAvps() != null
                && ((message.getAvps().getAvp(Avp.ORIGIN_HOST) != null)
                || (message.getAvps().getAvp(Avp.ORIGIN_REALM) != null) 
                && (message.getAvps().getAvp(Avp.DESTINATION_HOST) != null
                || (message.getAvps().getAvp(Avp.DESTINATION_REALM) != null)))
                ) {
            firewallPolicy = "DNAT_TO_HONEYPOT";
            
            String session_key = lua_hm.get("diameter_orig_host") + ":" + lua_hm.get("diameter_orig_realm");
            dnat_sessions.put(session_key, lua_hm.get("diameter_dest_host") + ":" + lua_hm.get("diameter_dest_realm"));
            
            message.getAvps().removeAvp(Avp.DESTINATION_REALM);
            message.getAvps().removeAvp(Avp.DESTINATION_HOST);
            // TODO usa raw AVP encoding, because aaa:// is added by jDiameter
            //try {
            message.getAvps().addAvp(Avp.DESTINATION_REALM, DiameterFirewallConfig.honeypot_diameter_realm, true, false, true);
            message.getAvps().addAvp(Avp.DESTINATION_HOST, DiameterFirewallConfig.honeypot_diameter_host, true, false, true);
            sendDiameterMessage(origin_asctn, payloadProtocolId, streamNumber, message, true, lua_hm);
            /*} catch (URISyntaxException ex) {
                java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
            } catch (UnknownServiceException ex) {
                java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
            }*/
            

        } else if (DiameterFirewallConfig.firewallPolicy == DiameterFirewallConfig.FirewallPolicy.ALLOW) {
            firewallPolicy = "ALLOW";
            sendDiameterMessage(origin_asctn, payloadProtocolId, streamNumber, message, true, lua_hm);
        }
        
        logger.info("Blocked message: Reason [" + reason + "] Policy [" + firewallPolicy + "] ");
                
        JSONObject json_alert = new JSONObject();
        logger.debug("============ LUA variables ============");
        // mThreat alerting
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        
            for (String key : lua_hm.keySet()) {
                logger.debug(key + ": " + lua_hm.get(key));

                String value = lua_hm.get(key);
                // Anonymize MSISDN, IMSI
                if (key.equals("diameter_imsi") || key.equals("diameter_msisdn")) {
                    // add salt before hashing
                    value = DiameterFirewallConfig.mthreat_salt + value;
                    value = DatatypeConverter.printHexBinary(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
                } 
                json_alert.put(key, value);
            }
            mThreat_alerts.add(json_alert.toJSONString());
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return;
    }
    

    public void onPayload(final Association asctn, final PayloadData pd) {
        
        logger.debug("[[[[[[[[[[    onPayload MainThread      ]]]]]]]]]]");
        
        threadPool.execute(new Runnable() {
            @Override
            public void run() {                  
        
                //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
                logger.debug("[[[[[[[[[[    onPayload      ]]]]]]]]]]");

                // LUA variables
                HashMap<String, String> lua_hmap = new HashMap<String, String>();
                lua_hmap.put("diameter_orig_host", "");
                lua_hmap.put("diameter_orig_realm", "");
                lua_hmap.put("diameter_dest_host", "");
                lua_hmap.put("diameter_dest_realm", "");
                lua_hmap.put("diameter_cc", "");    // command code
                lua_hmap.put("diameter_ai", "");    // application id
                lua_hmap.put("diameter_imsi", "");
                lua_hmap.put("diameter_msisdn", "");
               
                ByteBuffer buf = ByteBuffer.wrap(pd.getData());


                // Diameter firewall / filtering
                try {
                    Message msg = DiameterFirewall.parser.createMessage(buf);

                    //logger.debug("Message = " + msg.getAvps().toString());

                    // Parse Values
                    long ai = msg.getApplicationId();
                    lua_hmap.put("diameter_ai", Long.toString(ai));

                    int cc = msg.getCommandCode();
                    lua_hmap.put("diameter_cc", Integer.toString(cc));
                    
                    String dest_realm = "";
                    Avp avp = msg.getAvps().getAvp(Avp.DESTINATION_REALM);
                    if (avp != null && avp.getDiameterURI() != null && avp.getDiameterURI().getFQDN() != null) {
                        dest_realm = avp.getDiameterURI().getFQDN();
                    }
                    lua_hmap.put("diameter_dest_realm", dest_realm);

                    String dest_host = "";
                    avp = msg.getAvps().getAvp(Avp.DESTINATION_HOST);
                    if (avp != null && avp.getDiameterURI() != null && avp.getDiameterURI().getFQDN() != null) {
                        dest_host = avp.getDiameterURI().getFQDN();
                    }
                    lua_hmap.put("diameter_dest_host", dest_host);

                    String orig_realm = "";
                    avp = msg.getAvps().getAvp(Avp.ORIGIN_REALM);
                    if (avp != null && avp.getDiameterURI() != null && avp.getDiameterURI().getFQDN() != null) {
                        orig_realm = avp.getDiameterURI().getFQDN();
                    }
                    lua_hmap.put("diameter_orig_realm", orig_realm);

                    String orig_host = "";
                    avp = msg.getAvps().getAvp(Avp.ORIGIN_HOST);
                    if (avp != null && avp.getDiameterURI() != null && avp.getDiameterURI().getFQDN() != null) {
                        orig_host = avp.getDiameterURI().getFQDN();
                    }
                    lua_hmap.put("diameter_orig_host", orig_host);

                    String imsi = "";
                    avp = msg.getAvps().getAvp(Avp.USER_NAME);
                    if (avp != null && avp.getUTF8String() != null) {
                        imsi = avp.getUTF8String() ;
                    }
                    lua_hmap.put("diameter_imsi", imsi);

                    String msisdn = "";
                    avp = msg.getAvps().getAvp(1400 /*Subscription-Data in ULA on S6a*/);
                    if (avp != null && avp.getGrouped() != null && avp.getGrouped().getAvp(Avp.MSISDN) != null) {
                        msisdn = avp.getGrouped().getAvp(Avp.MSISDN).getUTF8String() ;
                    }
                    lua_hmap.put("diameter_msisdn", msisdn);

                    // ------ Request/Answer correlation --------
                    // Store the Diameter session, to be able encrypt also answers. Store Origin Realm from Request
                    if (!dest_realm.equals("") && msg.isRequest()) {
                        String session_id = ai + ":" + cc + ":" + dest_realm + ":" + msg.getEndToEndIdentifier();
                        diameter_sessions.put(session_id, orig_realm);
                    }
                    // ------------------------------------------

                    // ----------- Pass CER, DWR, DPR -----------
                    if (cc == 257 || cc == 280 || cc == 282) {           
                        sendDiameterMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, true, lua_hmap);
                        return;
                    }
                    // ------------------------------------------
                    
                    
                    // --------------- Diameter signature ---------------
                    // Verify both Requests and Answers containing Orig-Realm
                    if (!orig_realm.equals("") /*&& msg.isRequest()*/
                            && cc != CC_DTLS_HANDSHAKE_CLIENT && cc != CC_DTLS_HANDSHAKE_SERVER) {
                        // ------------- Diameter verify --------------
                        if (DiameterFirewallConfig.origin_realm_verify.containsKey(orig_realm)) {
                            String r = crypto.diameterVerify(msg, DiameterFirewallConfig.origin_realm_verify_signing_realm, dtls_engine_permanent_server);
                            if (!r.equals("")) {
                                firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, r, lua_hmap);
                                return;
                            }
                        } 
                        // No key to verify signature
                        else {
                            // TODO could initiate key autodiscovery
                        }
                    }
                    // ------------------------------------------
                    

                    // ---------- Diameter decryption -----------
                    // Diameter Decryption
                    // Requests containing Dest-Realm
                    
                    boolean needDTLSHandshake = false;
                    String needDTLSHandshakeReason = "";
                        
                    if (!dest_realm.equals("") && msg.isRequest() 
                            && cc != CC_DTLS_HANDSHAKE_CLIENT && cc != CC_DTLS_HANDSHAKE_SERVER) { 
                        
                        // DTLS decryption
                        if (dtls_engine_permanent_server.containsKey(orig_realm)) {
                            
                            boolean res = diameterDTLSDecrypt(msg, dtls_engine_permanent_server.get(orig_realm));
                            if (res == false ) {
                                needDTLSHandshake = true;
                                
                                needDTLSHandshakeReason = "needDTLSHandshake indicated, because failed to decrypt Request message from realm: " + orig_realm;
                            }
                            if (!dtls_engine_expiring_server.containsKey(orig_realm)) {
                                needDTLSHandshake = true;
                                
                                needDTLSHandshakeReason = "needDTLSHandshake indicated, because session has expired for realm: " + orig_realm;
                            }
                        } 
                        // No DTLS engine, but recieved DTLS encrypted data
                        else if (msg.getAvps().getAvp(AVP_DESS_ENCRYPTED, VENDOR_ID) != null) {
                            needDTLSHandshakeReason = "needDTLSHandshake indicated, because no DTLS engine, but recieved Request with DTLS encrypted data from realm: " + orig_realm;
                            
                            needDTLSHandshake = true;
                        }
                        // Asymmetric decryption
                        else if (DiameterFirewallConfig.destination_realm_decryption.containsKey(dest_realm)) {
                            KeyPair keyPair = DiameterFirewallConfig.destination_realm_decryption.get(dest_realm);

                            // decrypt
                            String r = crypto.diameterDecrypt(msg, keyPair);
                            if (!r.equals("")) {
                                firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, r, lua_hmap);
                                return;
                            }
                        }                     
                    }
                    // Answers without Dest-Realm, but seen previously Request
                    else if (!msg.isRequest()) {
                        String _dest_realm = "";
                        String session_id = ai + ":" + cc + ":" + orig_realm + ":" + msg.getEndToEndIdentifier();
                        if (diameter_sessions.containsKey(session_id)) {
                            _dest_realm = diameter_sessions.get(session_id);
                        }
                        
                        // DTLS decryption
                        if (dtls_engine_permanent_server.containsKey(orig_realm)) {
                            
                            boolean res = diameterDTLSDecrypt(msg, dtls_engine_permanent_server.get(orig_realm));
                            if (res == false) {
                                needDTLSHandshake = true;
                                
                                needDTLSHandshakeReason = "needDTLSHandshake indicated, because failed to decrypt Answer message from realm: " + orig_realm;
                            }
                            if (!dtls_engine_expiring_server.containsKey(orig_realm)) {
                                needDTLSHandshake = true;
                                
                                needDTLSHandshakeReason = "needDTLSHandshake indicated, because session has expired for realm: " + orig_realm;
                            }
                        }
                        // No DTLS engine, but recieved DTLS encrypted data
                        else if (msg.getAvps().getAvp(AVP_DESS_ENCRYPTED, VENDOR_ID) != null) {
                            needDTLSHandshake = true;
                            
                            needDTLSHandshakeReason = "needDTLSHandshake indicated, because no DTLS engine, but recieved Answer with DTLS encrypted data from realm: " + orig_realm;
                        }
                        // Asymmetric decryption
                        else if (DiameterFirewallConfig.destination_realm_decryption.containsKey(_dest_realm)) {
                            KeyPair keyPair = DiameterFirewallConfig.destination_realm_decryption.get(_dest_realm);
                            logger.debug("Diameter Decryption of Answer for Destination Realm = " + _dest_realm);

                            // decrypt
                            String r = crypto.diameterDecrypt(msg, keyPair);
                            if (!r.equals("")) {
                                firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, r, lua_hmap);
                                return;
                            }

                        }
                        // the session should not be removed, will auto expire and can be used in code later
                        // diameter_sessions.remove(session_id);
                        
                    }     
                    
                    // Initiate DTLS handshake backwards towards Origin-Realm
                    if (needDTLSHandshake
                        && DiameterFirewallConfig.dtls_encryption.equals("true")) {
                        if (!dtls_handshake_timer.containsKey(orig_realm)) {
                            // Only if no handshaking is ongoing
                            if (/*(!dtls_handshake_treads.containsKey(orig_realm) || !dtls_handshake_treads.get(orig_realm).isAlive())
                                    &&*/ /*!dtls_engine_handshaking_server.containsKey(orig_realm)
                                    &&*/ !dtls_engine_handshaking_client.containsKey(orig_realm)) {

                                logger.info("Initiate DTLS handshake client side, backwards towards Origin-Realm: " + orig_realm);
                                logger.info("Initiate DTLS handshake reason: " + needDTLSHandshakeReason);

                                final String o_realm = String.valueOf(orig_realm);

                                Thread t = new Thread(new Runnable() {
                                    @Override
                                    public void run() {
                                        try {

                                            // Create engine
                                            try {
                                                /*if (!dtls_engine_handshaking_client.containsKey(o_realm)) {
                                                    dtls_engine_handshaking_client.putIfAbsent(o_realm, dtls_createSSLEngine(true));
                                                }*/
                                                dtls_engine_handshaking_client.put(o_realm, dtls_createSSLEngine(true));

                                            } catch (Exception ex) {
                                                java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                                            }

                                            // Create socket if does not exist
                                            if (!datagramOverDiameterSocket_inbound_client.containsKey(o_realm)) {
                                                datagramOverDiameterSocket_inbound_client.put(o_realm, new ConcurrentLinkedQueue<DatagramOverDiameterPacket>());
                                            }


                                            dtls_handshake(dtls_engine_handshaking_client.get(o_realm), datagramOverDiameterSocket_inbound_client.get(o_realm), asctn, o_realm, "client", false);
                                        } catch (Exception ex) {
                                            //dtls_engine_handshaking_client.remove(o_realm);
                                            //dtls_handshake_treads.remove(o_realm);
                                            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                                        }
                                    }
                                });
                                //dtls_handshake_treads.put(orig_realm, t);
                                t.start();
                            }
                                
                            //logger.info("============ Sending DTLS Request ============ ");
                            //logger.debug("dtls_sessions.put " + message.getEndToEndIdentifier() + " " + _dest_realm);
                            //dtls_sessions.put(message.getEndToEndIdentifier(), _dest_realm);
                            logger.debug("dtls_sessions_reverse.put " + orig_realm + " " + /*message.getEndToEndIdentifier()*/null);
                            dtls_handshake_timer.put(orig_realm, /*message.getEndToEndIdentifier()*/null);
 
                            
                            
                          }
                    }
                    // ------------------------------------------


                    // Diameter firewall / filtering

                    // TODO Origin Host whitelist
                    // TODO Origin Realm whitelist

                    if(!DiameterFirewallConfig.check_diameter_application_id_whitelist(Long.toString(ai))) {
                        firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, "DIAMETER FW: Blocked Application ID = " + ai, lua_hmap);
                        return;
                    }

                    if(DiameterFirewallConfig.check_diameter_command_code_blacklist(Integer.toString(cc))) {
                        firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, "DIAMETER FW: Blocked Command Code = " + cc, lua_hmap);
                        return;
                    }


                    avp = msg.getAvps().getAvp(Avp.ORIGIN_HOST);
                    if (avp != null) {
                        logger.debug("Origin Host = " + avp.getDiameterURI().getFQDN());
                    }
                    avp = msg.getAvps().getAvp(Avp.ORIGIN_REALM);
                    if (avp != null) {
                        logger.debug("Origin Realm = " + avp.getDiameterURI().getFQDN());
                        if(DiameterFirewallConfig.check_diameter_origin_realm_blacklist(avp.getDiameterURI().getFQDN())) {
                            firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, "DIAMETER FW: Blocked Origin Realm = " + avp.getDiameterURI().getFQDN(), lua_hmap);
                            return;
                        }
                    }

                    // Diameter Cat2
                    if (msg.isRequest()) {
                        if (DiameterFirewallConfig.diameter_cat2_command_code_blacklist.containsKey(Integer.toString(cc))) {
                            // If towards HPLMN and not originated from HPLMN
                            if (DiameterFirewallConfig.hplmn_realms.containsKey(dest_realm)
                                    && !DiameterFirewallConfig.hplmn_realms.containsKey(orig_realm)) {

                                // Drop if message targets IMSI in HPLMN
                                if (imsi != null) {
                                    // IMSI prefix check
                                    for (String imsi_prefix: DiameterFirewallConfig.hplmn_imsi.keySet()) {
                                        if (imsi.startsWith(imsi_prefix)) {
                                            // logger.info("============ Diameter Cat2 Blocked Command Code = " + cc" ============");
                                            firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, "DIAMETER FW (Cat2): Blocked targeting home IMSI", lua_hmap);
                                            return;
                                        }
                                    }
                                }
                            }

                        }
                    }
                    // -------------- Externel Firewall rules -----------------
                    if (externalFirewallRules.diameterFirewallRules(asctn, pd) == false) {
                        firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, "DIAMETER FW: Match with Externel Firewall rules", lua_hmap);
                        return;
                    }

                    // -------------- LUA rules -----------------
                    ScriptEngineManager mgr = new ScriptEngineManager();
                    ScriptEngine eng = mgr.getEngineByName("luaj");
                    for (String key : lua_hmap.keySet()) {
                        eng.put(key, lua_hmap.get(key));
                    }

                    boolean lua_match = false;
                    int i;
                    for (i = 0; i < DiameterFirewallConfig.lua_blacklist_rules.size(); i++) {
                        try {
                            eng.eval("y = " + (String)DiameterFirewallConfig.lua_blacklist_rules.get(i));
                            boolean r =  Boolean.valueOf(eng.get("y").toString());
                            lua_match |= r;
                            if (r) {
                                //logger.debug("============ LUA rules blacklist: " + DiameterFirewallConfig.lua_blacklist_rules.get(i) + " ============");
                                //logger.debug("============ LUA variables ============");
                                //for (String key : lua_hmap.keySet()) {
                                //    logger.debug(key + ": " + lua_hmap.get(key));
                                //}
                                break;
                            }
                        } catch (ScriptException ex) {
                            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                    if (lua_match) {
                        firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, "DIAMETER FW: Match with Lua rule " + i, lua_hmap);
                        return;
                    }
                    // ------------------------------------------

                    // ------------- IDS API rules ---------------
                    if (connectorIDS != null) {
                        try {
                            if(connectorIDS.evalDiameterMessage(DatatypeConverter.printHexBinary(pd.getData())) == false) {
                                firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, "DIAMETER FW: Blocked by IDS " + i, lua_hmap);
                                return;
                            }
                        } catch (Exception ex) {
                            // TODO
                        }
                    }
                    // ------------------------------------------       

                    // Encryption Autodiscovery Sending Result
                    // Only targeting HPLMN
                    if (cc == CC_AUTO_ENCRYPTION
                        && DiameterFirewallConfig.encryption_autodiscovery.equals("true")
                        && msg.isRequest()
                        && DiameterFirewallConfig.hplmn_realms.containsKey(dest_realm)
                        && !DiameterFirewallConfig.hplmn_realms.containsKey(orig_realm)
                                ) {

                        if (DiameterFirewallConfig.destination_realm_decryption.containsKey(dest_realm)) {
                            KeyPair myKeyPair = DiameterFirewallConfig.destination_realm_decryption.get(dest_realm);
                            if (myKeyPair != null) {
                                Answer answer = ((IMessage)(msg)).createAnswer(ResultCode.SUCCESS);
                                
                                if (msg.getAvps().getAvp(Avp.DESTINATION_HOST) != null) {
                                    answer.getAvps().addAvp(Avp.ORIGIN_HOST, msg.getAvps().getAvp(Avp.DESTINATION_HOST).getRawData());
                                }
                                if (msg.getAvps().getAvp(Avp.DESTINATION_REALM) != null) {
                                    answer.getAvps().addAvp(Avp.ORIGIN_REALM, msg.getAvps().getAvp(Avp.DESTINATION_REALM).getRawData());
                                }

                                // Capabilities
                                // TODO
                                answer.getAvps().addAvp(AVP_AUTO_ENCRYPTION_CAPABILITIES, "Av1".getBytes(), VENDOR_ID, false, false);

                                // Realm
                                answer.getAvps().addAvp(AVP_AUTO_ENCRYPTION_REALM, dest_realm.getBytes(), VENDOR_ID, false, false);

                                // Public key type
                                String publicKeyType = "";
                                if (myKeyPair.getPublic() instanceof RSAPublicKey) {
                                    publicKeyType = "RSA";
                                } else if (myKeyPair.getPublic() instanceof ECPublicKey) {
                                    publicKeyType = "EC";
                                }
                                answer.getAvps().addAvp(AVP_AUTO_ENCRYPTION_PUBLIC_KEY_TYPE, publicKeyType.getBytes(), VENDOR_ID, false, false);

                                // Public key
                                answer.getAvps().addAvp(AVP_AUTO_ENCRYPTION_PUBLIC_KEY, myKeyPair.getPublic().getEncoded(), VENDOR_ID, false, false);

                                logger.info("============ Encryption Autodiscovery Sending Result ============ ");

                                // --------- Add also Diameter signature ------------
                                crypto.diameterSign(answer, DiameterFirewallConfig.origin_realm_signing, DiameterFirewallConfig.origin_realm_signing_signing_realm, dtls_engine_permanent_client);
                                // --------------------------------------------------
                                
                                sendDiameterMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), answer, false, lua_hmap);
                                return;
                            }
                        }
                    }

                    // Encryption Autodiscovery Receiving Result
                    // Only targeting HPLMN
                    if (cc == CC_AUTO_ENCRYPTION
                        && DiameterFirewallConfig.encryption_autodiscovery.equals("true")
                        && !msg.isRequest()
                        // Answer does not contain currently realms
                        //&& DiameterFirewallConfig.hplmn_realms.containsKey(dest_realm)
                        //&& !DiameterFirewallConfig.hplmn_realms.containsKey(orig_realm)
                       ) {

                        logger.info("============ Encryption Autodiscovery Receiving Result ============ ");
                        logger.debug("encryption_autodiscovery_sessions.containsKey " + new Long(msg.getEndToEndIdentifier()).toString());
                        if (encryption_autodiscovery_sessions.containsKey(msg.getEndToEndIdentifier())
                         // Answer does not contain currently realms
                         //&& encryption_autodiscovery_sessions.get(msg.getEndToEndIdentifier()).equals(origin_realm)
                         && msg.getAvps() != null) {
                            logger.debug("Processing Autodiscovery Result");

                            // Capabilities
                            // TODO

                            // Realm prefix
                            String realm = "";
                            if (msg.getAvps().getAvp(AVP_AUTO_ENCRYPTION_REALM, VENDOR_ID) != null) {
                                byte[] d2 = msg.getAvps().getAvp(AVP_AUTO_ENCRYPTION_REALM, VENDOR_ID).getOctetString();
                                realm = new String(d2);
                            }

                            // Public key type
                            String publicKeyType = "RSA";
                            if (msg.getAvps().getAvp(AVP_AUTO_ENCRYPTION_PUBLIC_KEY_TYPE, VENDOR_ID) != null) {
                                byte[] d3 = msg.getAvps().getAvp(AVP_AUTO_ENCRYPTION_PUBLIC_KEY_TYPE, VENDOR_ID).getOctetString();

                                publicKeyType = new String(d3);                       
                            }

                            // Public key
                            if (msg.getAvps().getAvp(AVP_AUTO_ENCRYPTION_PUBLIC_KEY) != null) {
                                byte[] d4 = msg.getAvps().getAvp(AVP_AUTO_ENCRYPTION_PUBLIC_KEY).getOctetString();
                                // TODO add method into config to add public key
                                byte[] publicKeyBytes =  d4;
                                try {
                                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                                    PublicKey publicKey = null;

                                    if (publicKeyType.equals("RSA")) {
                                        publicKey = keyFactoryRSA.generatePublic(pubKeySpec);
                                    } else if (publicKeyType.equals("EC")) {
                                        publicKey = keyFactoryEC.generatePublic(pubKeySpec);
                                    }
                                    logger.debug("Adding public key for realm = " + realm);
                                    DiameterFirewallConfig.destination_realm_encryption.put(realm, publicKey);
                                } catch (InvalidKeySpecException ex) {
                                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                                }
                            }
                        }

                        // do not forward message
                        return;
                    }
                    
                    // DTLS processing inbound handshake messages
                    // Only targeting HPLMN
                    if ((cc == CC_DTLS_HANDSHAKE_CLIENT || cc == CC_DTLS_HANDSHAKE_SERVER)
                        && DiameterFirewallConfig.dtls_encryption.equals("true")
                        //&& msg.isRequest()
                        && DiameterFirewallConfig.hplmn_realms.containsKey(dest_realm)
                        && !DiameterFirewallConfig.hplmn_realms.containsKey(orig_realm)
                                ) {
                        
                                // process only requests
                                if (msg.isRequest()) {
                                    if (msg.getAvps() != null) {
                                        if (msg.getAvps().getAvp(AVP_DESS_DTLS_DATA, VENDOR_ID) != null) {

                                            logger.info("Received DTLS handshake message from realm: " + orig_realm);

                                            // Request (client -> server)
                                            if (cc == CC_DTLS_HANDSHAKE_CLIENT) {
                                            //if (msg.isRequest()) {

                                                // Create socket if does not exists
                                                if (!datagramOverDiameterSocket_inbound_server.containsKey(orig_realm)) {
                                                    datagramOverDiameterSocket_inbound_server.put(orig_realm, new ConcurrentLinkedQueue<DatagramOverDiameterPacket>());
                                                }

                                                datagramOverDiameterSocket_inbound_server.get(orig_realm).add(new DatagramOverDiameterPacket(orig_realm, new DatagramPacket(msg.getAvps().getAvp(AVP_DESS_DTLS_DATA, VENDOR_ID).getOctetString(), msg.getAvps().getAvp(AVP_DESS_DTLS_DATA, VENDOR_ID).getOctetString().length)));


                                                boolean needHandshake = false;
                                                String needHandshakeReason = "";

                                                try {

                                                    // new handshaking peer
                                                    if(!dtls_engine_handshaking_server.containsKey(orig_realm)) {
                                                        needHandshake = true;

                                                        needHandshakeReason = "needDTLSHandshake indicated, because new handshaking client detected. Peer: " + orig_realm;
                                                    }
                                                    // no thread exist
                                                    /*else if (!dtls_handshake_treads.containsKey(orig_realm)){
                                                        needHandshake = true;

                                                        needHandshakeReason = "Initiate DTLS, because handshaking thread does not exist anymore. Peer: " + orig_realm;
                                                    }*/
                                                    /*// thread not active
                                                    else if (!dtls_handshake_treads.get(orig_realm).isAlive()){
                                                        needHandshake = true;

                                                        needHandshakeReason = "Initiate DTLS, because handshaking thread is not alive. Peer: " + orig_realm;
                                                    }*/
                                                    /*// NOT_HANDSHAKING status
                                                    else if (dtls_engine.get(orig_realm).getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING){
                                                        needHandshake = true;

                                                        needHandshakeReason = "Initiate DTLS, because in NOT_HANDSHAKING status";
                                                    }*/

                                                    // dispatch handshake in new thread
                                                    if(needHandshake) {
                                                        // Only if no server handshaking is ongoing

                                                        if (/*(!dtls_handshake_treads.containsKey(orig_realm) || !dtls_handshake_treads.get(orig_realm).isAlive())
                                                                && */!dtls_engine_handshaking_server.containsKey(orig_realm)) {

                                                            logger.info("Initiate DTLS handshake server side for peer: " + orig_realm);
                                                            logger.info("Initiate DTLS handshake reason: " + needHandshakeReason);

                                                            final String o_realm = String.valueOf(orig_realm);

                                                            Thread t = new Thread(new Runnable() {
                                                                @Override
                                                                public void run() {
                                                                    try {
                                                                        /*if(!dtls_engine_handshaking_server.containsKey(o_realm)) {
                                                                            dtls_engine_handshaking_server.putIfAbsent(o_realm, dtls_createSSLEngine(false));
                                                                        }*/
                                                                        dtls_engine_handshaking_server.put(o_realm, dtls_createSSLEngine(false));

                                                                        dtls_handshake(dtls_engine_handshaking_server.get(o_realm), datagramOverDiameterSocket_inbound_server.get(o_realm), /*datagramOverDiameterSocket_outbound*/ asctn, o_realm, "server", false);
                                                                    } catch (Exception ex) {
                                                                        //dtls_engine_handshaking_server.remove(o_realm);
                                                                        //dtls_handshake_treads.remove(o_realm);
                                                                        java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                                                                    }
                                                                }
                                                            });
                                                            //dtls_handshake_treads.put(orig_realm, t);
                                                            t.start();

                                                        }

                                                    }

                                                } catch (Exception ex) {
                                                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                                                }
                                            } 
                                            // Answer (server -> client)
                                            else if (cc == CC_DTLS_HANDSHAKE_SERVER) {
                                            //else {

                                                // Create socket if does not exists
                                                if (!datagramOverDiameterSocket_inbound_client.containsKey(orig_realm)) {
                                                    datagramOverDiameterSocket_inbound_client.put(orig_realm, new ConcurrentLinkedQueue<DatagramOverDiameterPacket>());
                                                }

                                                datagramOverDiameterSocket_inbound_client.get(orig_realm).add(new DatagramOverDiameterPacket(orig_realm, new DatagramPacket(msg.getAvps().getAvp(AVP_DESS_DTLS_DATA, VENDOR_ID).getOctetString(), msg.getAvps().getAvp(AVP_DESS_DTLS_DATA, VENDOR_ID).getOctetString().length)));

                                            }
                                            
                                            // produce DTLS Diameter Answer message
                                            Answer answer = ((IMessage)(msg)).createAnswer(ResultCode.SUCCESS);
                                            if (msg.getAvps().getAvp(Avp.DESTINATION_HOST) != null) {
                                                answer.getAvps().addAvp(Avp.ORIGIN_HOST, msg.getAvps().getAvp(Avp.DESTINATION_HOST).getRawData());
                                            }
                                            if (msg.getAvps().getAvp(Avp.DESTINATION_REALM) != null) {
                                                answer.getAvps().addAvp(Avp.ORIGIN_REALM, msg.getAvps().getAvp(Avp.DESTINATION_REALM).getRawData());
                                            }
                                            sendDiameterMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), answer, false, lua_hmap);
                                        }
                                    }
                                } 
                     
                        return;
                    }
                    // DTLS answer messages
                    // Only targeting HPLMN
                    if ((cc == CC_DTLS_HANDSHAKE_CLIENT || cc == CC_DTLS_HANDSHAKE_SERVER)
                        && DiameterFirewallConfig.dtls_encryption.equals("true")
                        && !msg.isRequest()) {
                         
                            // Drop DTLS answers
                            return;       
                    }

                    // ---------- Diameter encryption -----------
                    String session_id = ai + ":" +  cc + ":" +  orig_realm + ":" + msg.getEndToEndIdentifier();

                    // Requests containing Dest-Realm
                    if (!dest_realm.equals("") && msg.isRequest()) {
                        // DTLS encryption
                        if (dtls_engine_permanent_client.containsKey(dest_realm)) {
                            
                            boolean res = diameterDTLSEncrypt(msg, dtls_engine_permanent_client.get(dest_realm));
                            // unable to encrypt, better drop the DTLS engine
                            if (res == false) {
                                // expire session, should trigger new DTLS handshake
                                dtls_engine_expiring_client.remove(dest_realm);
                            }
                            
                            
                        }
                        // Asymmetric encryption
                        else if (DiameterFirewallConfig.destination_realm_encryption.containsKey(dest_realm)) {
                            PublicKey publicKey = DiameterFirewallConfig.destination_realm_encryption.get(dest_realm);
                            logger.debug("Diameter Encryption of Request for Destination Realm = " + dest_realm);

                            // encrypt
                            // diameterEncrypt(msg, publicKey);
                            // changed to v2 to use encrypted grouped AVP
                            crypto.diameterEncrypt_v2(msg, publicKey);
                        }
                    }
                    // Answers without Dest-Realm, but seen previous Request
                    else if (!msg.isRequest()
                            && diameter_sessions.containsKey(session_id) 
                      ) {
                        String _dest_realm = diameter_sessions.get(session_id);
                        
                        // DTLS encryption
                        if (dtls_engine_permanent_client.containsKey(_dest_realm)) {
                            
                            boolean res = diameterDTLSEncrypt(msg, dtls_engine_permanent_client.get(_dest_realm));
                            // unable to encrypt, better drop the DTLS engine
                            if (res == false) {
                                // TODO add handling
                                /*if (dtls_engine.get(dest_realm).getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                                    dtls_engine.remove(dest_realm);

                                    if (!dtls_handshake_treads.containsKey(dest_realm)) {
                                        dtls_handshake_treads.get(dest_realm).interrupt();
                                        dtls_handshake_treads.remove(dest_realm);
                                    }
                                }*/
                            }
                            
                        }
                        // Asymmetric encryption
                        else if (DiameterFirewallConfig.destination_realm_encryption.containsKey(_dest_realm)) {

                            PublicKey publicKey = DiameterFirewallConfig.destination_realm_encryption.get(_dest_realm);
                            logger.debug("Diameter Encryption of Answer for Destination Realm = " + _dest_realm);

                            // encrypt
                            // diameterEncrypt(msg, publicKey);
                            // changed to v2 to use encrypted grouped AVP
                            crypto.diameterEncrypt_v2(msg, publicKey);
                        }

                        // the session should not be removed, will auto expire and can be used in code later
                        // diameter_sessions.remove(session_id);

                    }
                    
                    // --------------- Diameter signature ---------------
                    // Sign both Requests and Answers containing Orig-Realm
                    if (!orig_realm.equals("") /*&& msg.isRequest()*/) {
                        // --------------------------------------------
                        // ------------- Diameter signing -------------
                        
                        /*if (DiameterFirewallConfig.origin_realm_signing.containsKey(orig_realm)) {
                            KeyPair keyPair = DiameterFirewallConfig.origin_realm_signing.get(orig_realm);
                            crypto.diameterSign(msg, keyPair, origin_realm_signing_signing_realm.get(orig_realm));
                        }*/
                        crypto.diameterSign(msg, DiameterFirewallConfig.origin_realm_signing, DiameterFirewallConfig.origin_realm_signing_signing_realm, dtls_engine_permanent_client);
                        
                        // --------------------------------------------
                    }
                    // ------------------------------------------
                    
                    // ------------ DTLS Encryption client handshake initialization ------------ 
                    if (DiameterFirewallConfig.dtls_encryption.equals("true")
                            &&
                            // If not encrypted Requests towards non HPLMN
                            ((msg.isRequest()
                            && !DiameterFirewallConfig.hplmn_realms.containsKey(dest_realm)
                            && DiameterFirewallConfig.hplmn_realms.containsKey(orig_realm)) ||
                            // In not encrypted Answers towards non HPLMN
                            (!msg.isRequest()
                            && diameter_sessions.containsKey(session_id))
                            && !DiameterFirewallConfig.hplmn_realms.containsKey(diameter_sessions.get(session_id)))
                     ) {
                        String _dest_realm = dest_realm;
                        if(!msg.isRequest()) {
                            _dest_realm = diameter_sessions.get(session_id);
                        }
                        // ------------ DTLS Encryption client handshake initialization ------------ 
                        if (!dtls_handshake_timer.containsKey(_dest_realm)) {

                            if(!dtls_engine_expiring_client.containsKey(_dest_realm) && !dtls_engine_handshaking_client.containsKey(_dest_realm)) {

                                try {

                                    logger.info("Initiate DTLS handshake client side for realm: " + _dest_realm);

                                    final String d_realm = String.valueOf(_dest_realm);

                                    Thread t = new Thread(new Runnable() {
                                        @Override
                                        public void run() {
                                            try {

                                                /*if (!dtls_engine_handshaking_client.containsKey(d_realm)) {
                                                    dtls_engine_handshaking_client.putIfAbsent(d_realm, dtls_createSSLEngine(true));
                                                }*/
                                                dtls_engine_handshaking_client.put(d_realm, dtls_createSSLEngine(true));

                                                // Create socket if does not exists
                                                if (!datagramOverDiameterSocket_inbound_client.containsKey(d_realm)) {
                                                    datagramOverDiameterSocket_inbound_client.put(d_realm, new ConcurrentLinkedQueue<DatagramOverDiameterPacket>());
                                                }

                                                dtls_handshake(dtls_engine_handshaking_client.get(d_realm), datagramOverDiameterSocket_inbound_client.get(d_realm), asctn, d_realm, "client", true);
                                            } catch (Exception ex) {
                                                //dtls_engine_handshaking_client.remove(d_realm);
                                                java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                                            }
                                        }
                                    });
                                    //dtls_handshake_treads.put(orig_realm, t);
                                    t.start();


                                } catch (Exception ex) {
                                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                                }

                                //logger.info("============ Sending DTLS Request ============ ");
                                //logger.debug("dtls_sessions.put " + message.getEndToEndIdentifier() + " " + _dest_realm);
                                //dtls_sessions.put(message.getEndToEndIdentifier(), _dest_realm);
                                logger.debug("dtls_sessions_reverse.put " + _dest_realm + " " + /*message.getEndToEndIdentifier()*/null);
                                dtls_handshake_timer.put(_dest_realm, /*message.getEndToEndIdentifier()*/null);
                                
                            }
                        }
                    }
                    // ------------ Encryption Autodiscovery initial message ------------ 
                    else if (DiameterFirewallConfig.encryption_autodiscovery.equals("true")
                            &&
                            // If not encrypted Requests towards non HPLMN
                            ((msg.isRequest()
                            && !DiameterFirewallConfig.hplmn_realms.containsKey(dest_realm)
                            && DiameterFirewallConfig.hplmn_realms.containsKey(orig_realm)) ||
                            // In not encrypted Answers towards non HPLMN
                            (!msg.isRequest()
                            && diameter_sessions.containsKey(session_id))
                            && !DiameterFirewallConfig.hplmn_realms.containsKey(diameter_sessions.get(session_id)))
                     ) {
                        String _dest_realm = dest_realm;
                        if(!msg.isRequest()) {
                            _dest_realm = diameter_sessions.get(session_id);
                        }

                        // ------------ Encryption Autodiscovery initial message ------------ 
                        if (!encryption_autodiscovery_sessions_reverse.containsKey(_dest_realm)) {

                            //IMessage message = parser.createEmptyMessage((IMessage)msg, CC_AUTO_ENCRYPTION);
                            IMessage message = parser.createEmptyMessage(CC_AUTO_ENCRYPTION, AI_DESS_INTERFACE);
                            
                            // Workaround. E2E ID long value should be clamp to 32bit before use. It is clamped in proto encoding. 
                            // See jDiamter MessageParser.java, Line 111. long endToEndId = ((long) in.readInt() << 32) >>> 32;
                            long e2e_id = ((long) message.getEndToEndIdentifier() << 32) >>> 32;
                            message.setEndToEndIdentifier(e2e_id);
                            
                            message.setHopByHopIdentifier(randomGenerator.nextLong());
                            //

                            // to this as soon as possible to prevent concurrent threads to duplicate the autodiscovery
                            logger.debug("encryption_autodiscovery_sessions.put " + message.getEndToEndIdentifier() + " " + _dest_realm);
                            encryption_autodiscovery_sessions.put(message.getEndToEndIdentifier(), _dest_realm);
                            logger.debug("encryption_autodiscovery_sessions_reverse.put " + _dest_realm + " " + message.getEndToEndIdentifier());
                            encryption_autodiscovery_sessions_reverse.put(_dest_realm, message.getEndToEndIdentifier());

                            /*if(!msg.isRequest()) {
                                message.setRequest(true);
                                // TODO usa raw AVP encoding, because aaa:// is added by jDiameter
                                message.getAvps().addAvp(Avp.DESTINATION_REALM, _dest_realm, true, false, true);
                            }
                            message.setHeaderApplicationId(AI_DESS_INTERFACE);*/
                            
                            message.setRequest(true);
                            message.getAvps().addAvp(Avp.DESTINATION_REALM, _dest_realm, true, false, true);

                            avp = msg.getAvps().getAvp(Avp.ORIGIN_REALM);
                            if (avp != null) {
                                message.getAvps().addAvp(avp.getCode(), avp.getRawData(), avp.getVendorId(), avp.isMandatory(), avp.isEncrypted());
                            }

                            // --------- Add also Diameter signature ------------
                            /*if (DiameterFirewallConfig.origin_realm_signing.containsKey(orig_realm)) {
                                KeyPair keyPair = DiameterFirewallConfig.origin_realm_signing.get(orig_realm);
                                crypto.diameterSign(message, keyPair, DiameterFirewallConfig.origin_realm_signing_signing_realm.get(orig_realm));
                            }*/
                            crypto.diameterSign(message, DiameterFirewallConfig.origin_realm_signing, DiameterFirewallConfig.origin_realm_signing_signing_realm, dtls_engine_permanent_client);
                            // --------------------------------------------------

                            logger.info("============ Sending Autodiscovery Request ============ ");

                            sendDiameterMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), message, true, lua_hmap);
                        }
                    }                   
                    // -------------------------------------------------

                    sendDiameterMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, true, lua_hmap);

                } catch (AvpDataException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeyException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                }/* catch (URISyntaxException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (UnknownServiceException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                }*/
        
            }
        });
        
    }

    public void onServiceStarted() {
        logger.debug("[[[[[[[[[[    onServiceStarted      ]]]]]]]]]]");
    }

    public void onServiceStopped() {
        logger.debug("[[[[[[[[[[    onServiceStopped      ]]]]]]]]]]");
    }

    public void onRemoveAllResources() {
        logger.debug("[[[[[[[[[[    onRemoveAllResources      ]]]]]]]]]]");
    }

    public void onServerAdded(org.mobicents.protocols.api.Server server) {
        logger.debug("[[[[[[[[[[    onServerAdded      ]]]]]]]]]]");
    }

    public void onServerRemoved(org.mobicents.protocols.api.Server server) {
        logger.debug("[[[[[[[[[[    onServerRemoved      ]]]]]]]]]]");
    }

    public void onAssociationAdded(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationAdded      ]]]]]]]]]]");
    }

    public void onAssociationRemoved(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationRemoved      ]]]]]]]]]]");
    }

    public void onAssociationStarted(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationStarted      ]]]]]]]]]]");
    }

    public void onAssociationStopped(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationStopped      ]]]]]]]]]]");
    }

    public void onAssociationUp(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationUp      ]]]]]]]]]]");
        if (asctn != null) {
            logger.warn(String.format("SCTP AssociationUp name=%s peer=%s", asctn.getName(), asctn.getPeerAddress()));
        }
    }

    public void onAssociationDown(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationDown      ]]]]]]]]]]");
        if (asctn != null) {
            logger.warn(String.format("SCTP AssociationDown name=%s peer=%s", asctn.getName(), asctn.getPeerAddress()));
        }
    }

    public void onNewRemoteConnection(Server server, Association asctn) {
        logger.debug("[[[[[[[[[[    onNewRemoteConnection      ]]]]]]]]]]");
        
        try {
            asctn.acceptAnonymousAssociation(this);
            
            this.anonymousAssociations.add(asctn);
            
        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void onCommunicationUp(Association asctn, int maxInboundStreams, int maxOutboundStreams) {
        logger.debug("[[[[[[[[[[    onCommunicationUp      ]]]]]]]]]]");
        logger.debug("maxInboundStreams = " + maxInboundStreams);
        logger.debug("maxOutoundStreams = " + maxOutboundStreams);
        
        sctpAssciationsMaxInboundStreams.put(asctn, maxInboundStreams);
        sctpAssciationsMaxOutboundStreams.put(asctn, maxOutboundStreams);
        
    }

    public void onCommunicationShutdown(Association asctn) {
        logger.debug("[[[[[[[[[[    onCommunicationShutdown      ]]]]]]]]]]");
        
        if(this.anonymousAssociations.contains(asctn)) {
            this.anonymousAssociations.remove(asctn);
        }
        
    }

    public void onCommunicationLost(Association asctn) {
        logger.debug("[[[[[[[[[[    onCommunicationLost      ]]]]]]]]]]");
    }

    public void onCommunicationRestart(Association asctn) {
        logger.debug("[[[[[[[[[[    onNewRemoteConnection      ]]]]]]]]]]");
        
    }
    
    public void inValidStreamId(PayloadData pd) {
        logger.debug("[[[[[[[[[[    inValidStreamId      ]]]]]]]]]]");
    }
    
    /**
     * Method to return status of the firewall. 
     * Status can be retrieved over REST API.
     * 
     */
    public static String getStatus() {
        String s = "";
        
        s += "Jetty Server Status = " + jettyServer.getState() + "\n";
        s += "Jetty Date = " + jettyServer.getDateField().toString() + "\n";
        s += "Jetty URI = " + jettyServer.getURI().toString() + "\n";
        s += "\n";
        s += "SCTP Associations\n";
        for (Map.Entry<String, Association> a : sctpManagement.getAssociations().entrySet()) {
            s += " Name = " + a.getKey() + "\n";
            s += " Details = " + a.getValue().toString() + "\n";
            s += " isStarted = " + a.getValue().isStarted() + "\n";
            s += " isConnected = " + a.getValue().isConnected() + "\n";
        }
        s += "\n";
        s += "SCTP Servers = " + sctpManagement.getServers().toString() + "\n";
        s += "\n";
        
        s += "OS statistics\n";
        s += " Available processors (cores): " + Runtime.getRuntime().availableProcessors() + "\n";
        s += " Free memory (bytes): " + Runtime.getRuntime().freeMemory() + "\n";
        long maxMemory = Runtime.getRuntime().maxMemory();
        s += " Maximum memory (bytes): " + (maxMemory == Long.MAX_VALUE ? "no limit" : maxMemory) + "\n";
        s += " Total memory available to JVM (bytes): " + Runtime.getRuntime().totalMemory() + "\n";
        File[] roots = File.listRoots();
        /* For each filesystem root, print some info */
        for (File root : roots) {
            s += " File system root: " + root.getAbsolutePath() + "\n";
            s += " Total space (bytes): " + root.getTotalSpace() + "\n";
            s += " Free space (bytes): " + root.getFreeSpace() + "\n";
            s += " Usable space (bytes): " + root.getUsableSpace() + "\n";
        }
        s += "\n";
        s += "Network interfaces\n";
        try {
            Enumeration<NetworkInterface> nets;
            nets = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface netint : Collections.list(nets)) {
                s += " Display name: " + netint.getDisplayName() + "\n";
                s += " Name: " + netint.getName() + "\n";
                Enumeration<InetAddress> inetAddresses = netint.getInetAddresses();
                for (InetAddress inetAddress : Collections.list(inetAddresses)) {
                    s += " InetAddress: " + inetAddress + "\n";
                }
            }
        } catch (SocketException ex) {
            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return s;
    }    
    
    /**
     * Get DTSL context
     */
    SSLContext dtls_getDTLSContext() throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        KeyStore ts = KeyStore.getInstance("JKS");

        char[] passphrase = dtls_passwd.toCharArray();

        try (FileInputStream fis = new FileInputStream(dtls_keyFilename)) {
            ks.load(fis, passphrase);
        }

        try (FileInputStream fis = new FileInputStream(dtls_trustFilename)) {
            ts.load(fis, passphrase);
        }

        kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, passphrase);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);

        SSLContext sslCtx = SSLContext.getInstance("DTLS");

        
        TrustManager tm = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };
        
        //sslCtx.init(kmf.getKeyManagers(), /*tmf.getTrustManagers()*/new TrustManager[] { tm }, /*null*/new java.security.SecureRandom());
        sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new java.security.SecureRandom());

        return sslCtx;
    }
    /**
     * Create engine for DTLS operations
     */
    SSLEngine dtls_createSSLEngine(boolean isClient) throws Exception {
        SSLContext context = dtls_getDTLSContext();
        SSLEngine engine = context.createSSLEngine();

        SSLParameters paras = engine.getSSLParameters();
        paras.setMaximumPacketSize(DTLS_MAXIMUM_PACKET_SIZE);

        engine.setUseClientMode(isClient);
        engine.setSSLParameters(paras);
        
        // Server requests client certificate authentication
        if (!isClient) {
            engine.setNeedClientAuth(true);
        }

        return engine;
    }
    
    /**
     * DTLS retransmission if timeout
     */
    boolean dtls_onReceiveTimeout(SSLEngine engine, /*SocketAddress socketAddr,*/ String peer_realm, 
            String side, List<DatagramOverDiameterPacket> packets) throws Exception {

        SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
        if (hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            return false;
        } else {
            // retransmission of handshake messages
            return dtls_produceHandshakePackets(engine, peer_realm, side, packets);
        }
    }
    
    /**
     * DTLS handshake
     */
    void dtls_handshake(SSLEngine engine, 
            /*DatagramSocket socket,*/
            ConcurrentLinkedQueue<DatagramOverDiameterPacket> datagramOverDiameterSocket_in, 
            //ConcurrentLinkedQueue<DatagramOverDiameterPacket> datagramOverDiameterSocket_out,
            Association asctn,
            /*SocketAddress peerAddr,*/
            String peer_realm,
            String side,
            boolean forwardIndicator) throws Exception {

        long _t = System.currentTimeMillis();
        long _end = _t + DTLS_MAX_HANDSHAKE_DURATION*1000;
        
        boolean endLoops = false;
        int loops = DTLS_MAX_HANDSHAKE_LOOPS;
        
        engine.beginHandshake();
        
        while (!endLoops && System.currentTimeMillis() < _end/*&&
                (dtls_serverException == null) && (dtls_clientException == null)*/) {

            if (--loops < 0) {
                throw new RuntimeException(
                        "Too much loops to produce handshake packets");
            }

            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            logger.info("DTLS " + side + "=======handshake(" + loops + ", " + hs + ")=======");
            if (hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP ||
                hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {

                logger.debug("DTLS " + side + ": " + "Receive DTLS records, handshake status is " + hs);

                ByteBuffer iNet;
                ByteBuffer iApp;
                if (hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                    byte[] buf = new byte[DTLS_BUFFER_SIZE];
                    DatagramOverDiameterPacket packet;// = new DatagramOverDiameterPacket( peer_realm, new DatagramPacket(buf, buf.length));
                    
                    //try {
                        //socket.receive(packet);
                    long t = System.currentTimeMillis();
                    long end = t + DTLS_SOCKET_TIMEOUT;
                    while(datagramOverDiameterSocket_in.isEmpty() && System.currentTimeMillis() < end) {
                        Thread.sleep(DTLS_SOCKET_THREAD_SLEEP);
                    }
                    packet = datagramOverDiameterSocket_in.poll();
                    
                    //} catch (SocketTimeoutException ste) {
                    if (packet == null) {
                        //log(side, "Warning: " + ste);
                        logger.warn("DTLS " + side + ": " + "Warning: DTLS_SOCKET_TIMEOUT " + DTLS_SOCKET_TIMEOUT);

                        List<DatagramOverDiameterPacket> packets = new ArrayList<>();
                        boolean hasFinished = dtls_onReceiveTimeout(engine, peer_realm, side, packets);

                        logger.debug("DTLS " + side + ": " + "Reproduced " + packets.size() + " packets");
                        for (DatagramOverDiameterPacket p : packets) {
                            //printHex("Reproduced packet", p.getP().getData(), p.getP().getOffset(), p.getP().getLength());
                            
                            //socket.send(p);
                            //datagramOverDiameterSocket_out.add(p);
                            
                            // initiate Diameter message
                            dtls_sendDatagramOverDiameter(asctn, peer_realm, p, side, forwardIndicator);
                            
                        }

                        if (hasFinished) {
                            logger.debug("DTLS " + side + ": " + "Handshake status is FINISHED "
                                    + "after calling onReceiveTimeout(), "
                                    + "finish the loop");
                            endLoops = true;
                        }

                        logger.debug("DTLS " + side + ": " + "New handshake status is "
                                + engine.getHandshakeStatus());

                        continue;
                    }

                    //printHex("Poll packet", packet.getP().getData(), packet.getP().getOffset(), packet.getP().getLength());
                            
                    logger.info("dtls_handshake: Read packet from datagramOverDiameterSocket_in");
                    iNet = ByteBuffer.wrap(packet.getP().getData(), 0, packet.getP().getLength());
                    iApp = ByteBuffer.allocate(DTLS_BUFFER_SIZE);                  
                } else {
                    iNet = ByteBuffer.allocate(0);
                    iApp = ByteBuffer.allocate(DTLS_BUFFER_SIZE);
                }

                SSLEngineResult r = engine.unwrap(iNet, iApp);
                SSLEngineResult.Status rs = r.getStatus();
                hs = r.getHandshakeStatus();
                if (rs == SSLEngineResult.Status.OK) {
                    // OK
                } else if (rs == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                    logger.debug("DTLS " + side + ": " + "BUFFER_OVERFLOW, handshake status is " + hs);

                    // the client maximum fragment size config does not work?
                    throw new Exception("Buffer overflow: " +
                        "incorrect client maximum fragment size");
                } else if (rs == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                    logger.debug("DTLS " + side + ": " + "BUFFER_UNDERFLOW, handshake status is " + hs);

                    // bad packet, or the client maximum fragment size
                    // config does not work?
                    if (hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                        throw new Exception("Buffer underflow: " +
                            "incorrect client maximum fragment size");
                    } // otherwise, ignore this packet
                } else if (rs == SSLEngineResult.Status.CLOSED) {
                    throw new Exception(
                            "SSL engine closed, handshake status is " + hs);
                } else {
                    throw new Exception("Can't reach here, result is " + rs);
                }

                if (hs == SSLEngineResult.HandshakeStatus.FINISHED) {
                    logger.debug("DTLS " + side + ": " + "Handshake status is FINISHED, finish the loop");
                    endLoops = true;
                }
            } else if (hs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                List<DatagramOverDiameterPacket> packets = new ArrayList<>();
                boolean hasFinished = dtls_produceHandshakePackets(
                    engine, /*peerAddr,*/ peer_realm, side, packets);

                logger.debug("DTLS " + side + ": " + "Produced " + packets.size() + " packets");
                for (DatagramOverDiameterPacket p : packets) {
                    //socket.send(p);
                    
                    
                    //datagramOverDiameterSocket_out.add(p);
                    // forward message
                    dtls_sendDatagramOverDiameter(asctn, peer_realm, p, side, forwardIndicator);                                
                    
                }

                if (hasFinished) {
                    logger.debug("DTLS " + side + ": " + "Handshake status is FINISHED "
                            + "after producing handshake packets, "
                            + "finish the loop");
                    endLoops = true;
                }
            } else if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                dtls_runDelegatedTasks(engine);
            } else if (hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                logger.debug("DTLS " + side + ": " +
                    "Handshake status is NOT_HANDSHAKING, finish the loop");
                endLoops = true;
            } else if (hs == SSLEngineResult.HandshakeStatus.FINISHED) {
                throw new Exception(
                        "Unexpected status, SSLEngine.getHandshakeStatus() "
                                + "shouldn't return FINISHED");
            } else {
                throw new Exception(
                        "Can't reach here, handshake status is " + hs);
            }
        }

        SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
        logger.debug("DTLS " + side + ": " + "Handshake finished, status is " + hs);

        if (engine.getHandshakeSession() != null) {
            throw new Exception(
                    "Handshake finished, but handshake session is not null");
        }

        SSLSession session = engine.getSession();
        if (session == null) {
            throw new Exception("Handshake finished, but session is null");
        }
        logger.info("DTLS " + side + ": " + "Negotiated protocol is " + session.getProtocol());
        logger.info("DTLS " + side + ": " + "Negotiated cipher suite is " + session.getCipherSuite());
        
        // store SSL engine only if some cipher is negotiated
        if (!session.getProtocol().equals("NONE") && !session.getCipherSuite().equals("SSL_NULL_WITH_NULL_NULL")) {
            if (side.equals("client")) {
                dtls_engine_permanent_client.put(peer_realm, engine);
                dtls_engine_expiring_client.put(peer_realm, engine);
                dtls_engine_handshaking_client.remove(peer_realm);
                datagramOverDiameterSocket_inbound_client.remove(peer_realm);
            } else if (side.equals("server")) {
                dtls_engine_permanent_server.put(peer_realm, engine);
                dtls_engine_expiring_server.put(peer_realm, engine);
                dtls_engine_handshaking_server.remove(peer_realm);
                datagramOverDiameterSocket_inbound_server.remove(peer_realm);
            }  else {
                logger.error("dtls_handshake: Not client and not server side.");
            }
            
            logger.info("DTLS " + side + ": " + "Storing the SSLengine for peer: " + peer_realm);
        }
        

        // handshake status should be NOT_HANDSHAKING
        //
        // According to the spec, SSLEngine.getHandshakeStatus() can't
        // return FINISHED.
        if (hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            throw new Exception("Unexpected handshake status " + hs);
        }
    }
    
    /**
     * DTLS produce handshake packets
     */
    boolean dtls_produceHandshakePackets(SSLEngine engine, /*SocketAddress socketAddr,*/ String peer_realm,
            String side, List<DatagramOverDiameterPacket> packets) throws Exception {

        long _t = System.currentTimeMillis();
        long _end = _t + DTLS_MAX_HANDSHAKE_DURATION*1000;

        boolean endLoops = false;
        int loops = DTLS_MAX_HANDSHAKE_LOOPS / 2;
        while (!endLoops && System.currentTimeMillis() < _end/*&&
                (dtls_serverException == null) && (dtls_clientException == null)*/) {

            if (--loops < 0) {
                throw new RuntimeException(
                        "Too much loops to produce handshake packets");
            }

            ByteBuffer oNet = ByteBuffer.allocate(DTLS_BUFFER_SIZE);
            ByteBuffer oApp = ByteBuffer.allocate(0);
            SSLEngineResult r = engine.wrap(oApp, oNet);
            oNet.flip();

            SSLEngineResult.Status rs = r.getStatus();
            SSLEngineResult.HandshakeStatus hs = r.getHandshakeStatus();
            logger.debug("DTLS " + side + ": " + "----produce handshake packet(" +
                    loops + ", " + rs + ", " + hs + ")----");
            if (rs == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                // the client maximum fragment size config does not work?
                throw new Exception("Buffer overflow: " +
                            "incorrect server maximum fragment size");
            } else if (rs == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                logger.debug("DTLS " + side + ": " +
                        "Produce handshake packets: BUFFER_UNDERFLOW occured");
                logger.debug("DTLS " + side + ": " +
                        "Produce handshake packets: Handshake status: " + hs);
                // bad packet, or the client maximum fragment size
                // config does not work?
                if (hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                    throw new Exception("Buffer underflow: " +
                            "incorrect server maximum fragment size");
                } // otherwise, ignore this packet
            } else if (rs == SSLEngineResult.Status.CLOSED) {
                throw new Exception("SSLEngine has closed");
            } else if (rs == SSLEngineResult.Status.OK) {
                // OK
            } else {
                throw new Exception("Can't reach here, result is " + rs);
            }

            // SSLEngineResult.Status.OK:
            if (oNet.hasRemaining()) {
                byte[] ba = new byte[oNet.remaining()];
                oNet.get(ba);
                DatagramOverDiameterPacket packet = createHandshakePacket(ba, peer_realm);
                packets.add(packet);
            }

            if (hs == SSLEngineResult.HandshakeStatus.FINISHED) {
                logger.debug("DTLS " + side + ": " + "Produce handshake packets: "
                            + "Handshake status is FINISHED, finish the loop");
                return true;
            }

            boolean endInnerLoop = false;
            SSLEngineResult.HandshakeStatus nhs = hs;
            while (!endInnerLoop) {
                if (nhs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    dtls_runDelegatedTasks(engine);
                } else if (nhs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP ||
                    nhs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN ||
                    nhs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

                    endInnerLoop = true;
                    endLoops = true;
                } else if (nhs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    endInnerLoop = true;
                } else if (nhs == SSLEngineResult.HandshakeStatus.FINISHED) {
                    throw new Exception(
                            "Unexpected status, SSLEngine.getHandshakeStatus() "
                                    + "shouldn't return FINISHED");
                } else {
                    throw new Exception("Can't reach here, handshake status is "
                            + nhs);
                }
                nhs = engine.getHandshakeStatus();
            }
        }

        return false;
    }

    /**
     * DTLS createHandshakePacket
     */
    DatagramOverDiameterPacket createHandshakePacket(byte[] ba, /*SocketAddress socketAddr*/ String peer_realm) {
        return new DatagramOverDiameterPacket(peer_realm, new DatagramPacket(ba, ba.length));
    }
    
    /**
     * DTLS run delegated tasks
     */
    void dtls_runDelegatedTasks(SSLEngine engine) throws Exception {
        Runnable runnable;
        while ((runnable = engine.getDelegatedTask()) != null) {
            runnable.run();
        }

        SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
        if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            throw new Exception("handshake shouldn't need additional tasks");
        }
    }
    
    void dtls_sendDatagramOverDiameter(Association asctn, String _peer_realm, DatagramOverDiameterPacket p, String side, boolean forwardIndicator) {
        
        IMessage message;
        
        if (side.equals("client")) {
            message = parser.createEmptyMessage(CC_DTLS_HANDSHAKE_CLIENT, AI_DESS_INTERFACE);
        } else if (side.equals("server")) {
            message = parser.createEmptyMessage(CC_DTLS_HANDSHAKE_SERVER, AI_DESS_INTERFACE);
        } else {
            logger.error("dtls_sendDatagramOverDiameter: Not client and not server side.");
            return;
        }
        message.setRequest(true);
        
        //IMessage message = parser.createEmptyMessage(CC_DTLS_HANDSHAKE, AI_DESS_INTERFACE);

        // Workaround. E2E ID long value should be clamp to 32bit before use. It is clamped in proto encoding. 
        // See jDiamter MessageParser.java, Line 111. long endToEndId = ((long) in.readInt() << 32) >>> 32;
        long e2e_id = ((long) message.getEndToEndIdentifier() << 32) >>> 32;
        message.setEndToEndIdentifier(e2e_id);
        
        message.setHopByHopIdentifier(randomGenerator.nextLong());
        //

        // to this as soon as possible to prevent concurrent threads to duplicate the autodiscovery
        /*logger.debug("encryption_autodiscovery_sessions.put " + message.getEndToEndIdentifier() + " " + _dest_realm);
        encryption_autodiscovery_sessions.put(message.getEndToEndIdentifier(), _dest_realm);
        logger.debug("encryption_autodiscovery_sessions_reverse.put " + _dest_realm + " " + message.getEndToEndIdentifier());
        encryption_autodiscovery_sessions_reverse.put(_dest_realm, message.getEndToEndIdentifier());*/

        //if(!msg.isRequest()) {
            //message.setRequest(true);
            // TODO usa raw AVP encoding, because aaa:// is added by jDiameter
            //message.getAvps().addAvp(Avp.DESTINATION_REALM, _dest_realm, true, false, true);
        //}
        
        // TODO currently used first HPLMN realm as orig realm
        //if (side.equals("client")) {
        //    message.setRequest(true);
        //} else if (side.equals("server")) {
        //    message.setRequest(false);
        //} else {
        //    logger.error("dtls_sendDatagramOverDiameter: Not client and not server side.");
        //}
        
        message.getAvps().addAvp(Avp.DESTINATION_REALM, _peer_realm, true, false, true);
        message.getAvps().addAvp(Avp.DESTINATION_HOST, _peer_realm, true, false, true);
        message.getAvps().addAvp(Avp.ORIGIN_REALM, DiameterFirewallConfig.hplmn_realms.firstKey(), true, false, true);
        message.getAvps().addAvp(Avp.ORIGIN_HOST, DiameterFirewallConfig.hplmn_realms.firstKey(), true, false, true);  
        message.getAvps().addAvp(AVP_DESS_DTLS_DATA, p.getP().getData(), VENDOR_ID, false, false);

        //message.setHeaderApplicationId(AI_DESS_INTERFACE);

        /*// --------- Add also Diameter signature ------------
        if (DiameterFirewallConfig.origin_realm_signing.containsKey(orig_realm)) {
            KeyPair keyPair = DiameterFirewallConfig.origin_realm_signing.get(orig_realm);
            crypto.diameterSign(message, keyPair, DiameterFirewallConfig.origin_realm_signing_signing_realm.get(orig_realm));
        }
        // --------------------------------------------------*/

        logger.info("============ Sending DTLS ============ ");

        
        // TODO currently use PID 0 and stream number 0
        sendDiameterMessage(asctn, 0, 0, message, forwardIndicator, null);
    }
    
    
    /**
     * DTLS encrypt byte buffer
     */
    boolean diameterDTLSEncryptBuffer(SSLEngine engine, ByteBuffer source, ByteBuffer appNet) throws Exception {

        //printHex("Received application data for Encrypt", source);
        
        List<DatagramPacket> packets = new ArrayList<>();
        SSLEngineResult r = engine.wrap(source, appNet);
        appNet.flip();

        SSLEngineResult.Status rs = r.getStatus();
        if (rs == SSLEngineResult.Status.BUFFER_OVERFLOW) {
            // the client maximum fragment size config does not work?
            logger.warn("Buffer overflow: " + "incorrect server maximum fragment size");
            return false;
        } else if (rs == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
            // unlikely
            logger.warn("Buffer underflow during wraping");
            return false;
        } else if (rs == SSLEngineResult.Status.CLOSED) {
            logger.warn("SSLEngine has closed");
            return false;
        } else if (rs == SSLEngineResult.Status.OK) {
            // OK
        } else {
            logger.warn("Can't reach here, result is " + rs);
            return false;
        }

        // SSLEngineResult.Status.OK:
        // printHex("Produced application data by Encrypt", appNet);
        return true;
    }
    
    /**
     * DTLS decrypt byte buffer
     */
    boolean diameterDTLSDecryptBuffer(SSLEngine engine, ByteBuffer source, ByteBuffer recBuffer) throws Exception {
     
        //printHex("Received application data for Decrypt", source);
        
        SSLEngineResult r = engine.unwrap(source, recBuffer);
        recBuffer.flip();
        
        SSLEngineResult.Status rs = r.getStatus();
        if (rs == SSLEngineResult.Status.BUFFER_OVERFLOW) {
            // the client maximum fragment size config does not work?
            logger.warn("Buffer overflow: " + "incorrect server maximum fragment size");
            return false;
        } else if (rs == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
            // unlikely
            logger.warn("Buffer underflow during wraping");
            return false;
        } else if (rs == SSLEngineResult.Status.CLOSED) {
            logger.warn("SSLEngine has closed");
            return false;
        } else if (rs == SSLEngineResult.Status.OK) {
            // OK
        } else {
            logger.warn("Can't reach here, result is " + rs);
            return false;
        }
        
        //printHex("Produced application data by Decrypt", recBuffer);
        return true;
    }
    
    /**
     * DTLS encrypt all AVPs
     * @param message
     * @param engine
     * @return 
     */
    public boolean _diameterDTLSEncrypt(Message message, SSLEngine engine) {
        
        logger.debug("== diameterDTLSEncrypt ==");
        
        /*if (engine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            logger.warn("== diameterDTLSEncrypt DTLS handshake not finnished ==");
            // consider it as ok, if the handshake is still ongoing
            return true;
        }*/
        
        AvpSet avps = message.getAvps();
        
        AvpSet erAvp = avps.addGroupedAvp(AVP_DESS_ENCRYPTED, VENDOR_ID, false, true);
        
        for (int i = 0; i < avps.size(); i++) {
            Avp a = avps.getAvpByIndex(i);
            
            //logger.debug("AVP[" + i + "] Code = " + a.getCode());
            
            if (
                    a.getCode() != Avp.ORIGIN_HOST &&
                    a.getCode() != Avp.ORIGIN_REALM &&
                    a.getCode() != Avp.DESTINATION_HOST &&
                    a.getCode() != Avp.DESTINATION_REALM &&
                    a.getCode() != Avp.SESSION_ID &&
                    a.getCode() != Avp.ROUTE_RECORD &&
                    a.getCode() != Crypto.AVP_ENCRYPTED &&
                    a.getCode() != Crypto.AVP_ENCRYPTED_GROUPED &&
                    a.getCode() != AVP_DESS_ENCRYPTED
                ) {
                    erAvp.addAvp(a.getCode(), a.getRawData(), a.getVendorId(), a.isMandatory(), a.isEncrypted());
                    avps.removeAvpByIndex(i);
                    i--;
            }
        }
        
        //byte[] d = a.getRawData();
        byte [] d = Utils.encodeAvpSet(erAvp);

        logger.debug("avps.size = " + erAvp.size());
        logger.debug("plainText = " + d.toString());
        logger.debug("plainText.size = " + d.length);

        /*// SPI(version) and TVP(timestamp)
        byte[] SPI = {0x00, 0x00, 0x00, 0x00};  // TODO
        byte[] TVP = {0x00, 0x00, 0x00, 0x00};

        long t = System.currentTimeMillis()/100;    // in 0.1s
        TVP[0] = (byte) ((t >> 24) & 0xFF);
        TVP[1] = (byte) ((t >> 16) & 0xFF);
        TVP[2] = (byte) ((t >>  8) & 0xFF);
        TVP[3] = (byte) ((t >>  0) & 0xFF);*/

        try {
            
            ByteBuffer cipherTextBuffer = ByteBuffer.allocate(DTLS_BUFFER_SIZE);
            boolean res = diameterDTLSEncryptBuffer(engine, ByteBuffer.wrap(d, 0, d.length), cipherTextBuffer);
            if (res == false) {
                logger.warn("diameterDTLSEncrypt: Failed encryption of DTLS data");
                return false;
            }
            
            byte[] cipherText = new byte[cipherTextBuffer.remaining()];
            cipherTextBuffer.get(cipherText);
            
            //logger.debug("Add AVP Grouped Encrypted. Current index");
            avps.removeAvp(AVP_DESS_ENCRYPTED, VENDOR_ID);
            avps.addAvp(AVP_DESS_ENCRYPTED, cipherText, VENDOR_ID, false, true);

        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return true;
    }

    /**
     * DTLS decrypt all AVPs
     * @param message
     * @param engine
     * @return 
     */
    public boolean _diameterDTLSDecrypt(Message message, SSLEngine engine) {
        
        logger.debug("== diameterDTLSDecrypt ==");
        
        /*if (engine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            logger.warn("== diameterDTLSDecrypt DTLS handshake not finnished ==");
            // consider it as ok, if the handshake is still ongoing
            return true;
        }*/
        
        AvpSet avps = message.getAvps();
        
        int avps_size = avps.size();
        
        
        for (int i = 0; i < avps_size; i++) {
            Avp a = avps.getAvpByIndex(i);
            
            //logger.debug("AVP[" + i + "] Code = " + a.getCode());
            
            if (a.getCode() == AVP_DESS_ENCRYPTED && a.isVendorId() && a.getVendorId() == VENDOR_ID) {
                AvpSetImpl _avps;
                try {
                    logger.debug("Diameter Decryption of Grouped Encrypted DTLS AVP");
                    byte[] b = a.getOctetString();
                    byte[] d = b;
                    /*// SPI(version) and TVP(timestamp)decrypt
                    byte[] SPI = {0x00, 0x00, 0x00, 0x00};
                    byte[] TVP = {0x00, 0x00, 0x00, 0x00};
                    byte[] d = null;
                    if (b.length >= SPI.length) {
                        SPI = Arrays.copyOfRange(b, 0, SPI.length);
                        d = Arrays.copyOfRange(b, SPI.length, b.length);
                    } else {
                        d = b;
                    }   // TODO verify SPI*/
                    
                    ByteBuffer decryptedTextBuffer = ByteBuffer.allocate(DTLS_BUFFER_SIZE);
                    boolean res = diameterDTLSDecryptBuffer(engine, ByteBuffer.wrap(d, 0, d.length), decryptedTextBuffer);
                    if (res == false) {
                        logger.warn("diameterDTLSDecrypt: Failed decryption of DTLS data");
                        return false;
                    }
                    
                    
                    if (decryptedTextBuffer.remaining() != 0) {
                        logger.debug("diameterDTLSDecrypt: Successful decryption of DTLS data");
                    }
                        
                    byte[] decryptedText = new byte[decryptedTextBuffer.remaining()];
                    decryptedTextBuffer.get(decryptedText);
                    
                    d = decryptedText;
                    
                    /*if (d.length < 4) {
                        logger.error("diameterDTLSDecrypt: Unable to decrypt data");
                        return false;
                    }
                    
                    // ---- Verify TVP from Security header ----
                    long t = System.currentTimeMillis()/100;    // in 0.1s
                    TVP[0] = (byte) ((t >> 24) & 0xFF);
                    TVP[1] = (byte) ((t >> 16) & 0xFF);
                    TVP[2] = (byte) ((t >>  8) & 0xFF);
                    TVP[3] = (byte) ((t >>  0) & 0xFF);
                    t = 0;
                    for (int j = 0; j < TVP.length; j++) {
                        t =  ((t << 8) + (TVP[j] & 0xff));
                    }

                    TVP[0] = d[0]; TVP[1] = d[1]; TVP[2] = d[2]; TVP[3] = d[3];
                    long t_tvp = 0;
                    for (int j = 0; j < TVP.length; j++) {
                        t_tvp =  ((t_tvp << 8) + (TVP[j] & 0xff));
                    }
                    if (Math.abs(t_tvp-t) > Crypto.diameter_tvp_time_window*10) {
                        return "DIAMETER FW: Blocked in decryption, Wrong timestamp in TVP (received: " + t_tvp + ", current: " + t + ")";
                    }
                    d = Arrays.copyOfRange(d, TVP.length, d.length);*/
                    // ---- End of Verify TVP ----
            
                    //logger.debug("Add AVP Decrypted. Current index = " + i);
                    //AvpImpl avp = new AvpImpl(code, (short) flags, (int) vendor, rawData);
                    //avps.insertAvp(i, ByteBuffer.wrap(cc).order(ByteOrder.BIG_ENDIAN).getInt(), d, false, false);
                    //logger.debug("decryptedText = " + decryptedText.toString());
                    //logger.debug("decryptedText.size = " + decryptedText.length);
                    _avps = (AvpSetImpl)Utils.decodeAvpSet(decryptedText, 0);
                    //logger.debug("SIZE = " + _avps.size());
                    
                    for (int j = 0; j < _avps.size(); j++) {
                        AvpImpl _a = (AvpImpl)_avps.getAvpByIndex(j);
                        logger.debug("addAVP = " + _a.getCode());
                        avps.insertAvp(i, _a.getCode(), _a.getRawData(), _a.vendorID, _a.isMandatory, _a.isEncrypted());
                    }
                    avps.removeAvpByIndex(i + _avps.size());
                    
                } catch (IOException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (AvpDataException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                }
  
            }
            
        }
        
        return true;
    }
    
    /**
     * DTLS encrypt for protected AVPs only (GSMA DESS)
     * @param message
     * @param engine
     * @return 
     */
    public boolean diameterDTLSEncrypt(Message message, SSLEngine engine) {
        
        logger.debug("== diameterDTLSEncrypt ==");
        
        /*if (engine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            logger.warn("== diameterDTLSEncrypt DTLS handshake not finnished ==");
            // consider it as ok, if the handshake is still ongoing
            return true;
        }*/
        
        AvpSet _avps = message.getAvps();
        
        // cloned AVPs
        AvpSet avps = ((Message) ((IMessage) message).clone()).getAvps();
        
        AvpSet erAvp = avps.addGroupedAvp(AVP_DESS_ENCRYPTED, VENDOR_ID, false, true);
        
        // Fill the AVP_ENCRYPTED_GROUPED_DTLS with cloned AVPs
        for (int i = 0; i <_avps.size(); i++) {
            Avp a = _avps.getAvpByIndex(i);
            
            //logger.debug("AVP[" + i + "] Code = " + a.getCode());
            
            if (
                    a.getCode() != Avp.ORIGIN_HOST &&
                    a.getCode() != Avp.ORIGIN_REALM &&
                    a.getCode() != Avp.DESTINATION_HOST &&
                    a.getCode() != Avp.DESTINATION_REALM &&
                    a.getCode() != Avp.SESSION_ID &&
                    a.getCode() != Avp.ROUTE_RECORD &&
                    a.getCode() != Crypto.AVP_ENCRYPTED &&
                    a.getCode() != Crypto.AVP_ENCRYPTED_GROUPED &&
                    a.getCode() != AVP_DESS_ENCRYPTED
                ) {
                    erAvp.addAvp(a.getCode(), a.getRawData(), a.getVendorId(), a.isMandatory(), a.isEncrypted());
                    //avps.removeAvpByIndex(i);
                    //i--;
            }
        }
        
        try {
            // Remove the non protected AVPs (which are not under grouped protected) from new AVP_ENCRYPTED_GROUPED_DTLS which contains cloned AVPs
            removeTheAVPs(erAvp, protectedAVPCodes, false);

            // Remove the protected AVPs from the original message
            removeTheAVPs(_avps, protectedAVPCodes, true);

            //byte[] d = a.getRawData();
                      
            byte [] d = Utils.encodeAvpSet(erAvp);

            logger.debug("avps.size = " + erAvp.size());
            logger.debug("plainText = " + d.toString());
            logger.debug("plainText.size = " + d.length);

            /*// SPI(version) and TVP(timestamp)
            byte[] SPI = {0x00, 0x00, 0x00, 0x00};  // TODO
            byte[] TVP = {0x00, 0x00, 0x00, 0x00};

            long t = System.currentTimeMillis()/100;    // in 0.1s
            TVP[0] = (byte) ((t >> 24) & 0xFF);
            TVP[1] = (byte) ((t >> 16) & 0xFF);
            TVP[2] = (byte) ((t >>  8) & 0xFF);
            TVP[3] = (byte) ((t >>  0) & 0xFF);*/

            
            ByteBuffer cipherTextBuffer = ByteBuffer.allocate(DTLS_BUFFER_SIZE);
            boolean res = diameterDTLSEncryptBuffer(engine, ByteBuffer.wrap(d, 0, d.length), cipherTextBuffer);
            if (res == false) {
                logger.warn("diameterDTLSEncrypt: Failed encryption of DTLS data");
                return false;
            }
            
            byte[] cipherText = new byte[cipherTextBuffer.remaining()];
            cipherTextBuffer.get(cipherText);
            
            //logger.debug("Add AVP Grouped Encrypted. Current index");
            //_avps.removeAvp(AVP_ENCRYPTED_GROUPED_DTLS);
            _avps.addAvp(AVP_DESS_ENCRYPTED, cipherText, VENDOR_ID, false, true);

        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return true;
    }

    
    /**
     * DTLS decrypt for protected AVPs only (GSMA DESS)
     * @param message
     * @param engine
     * @return 
     */
    public boolean diameterDTLSDecrypt(Message message, SSLEngine engine) {
        
        logger.debug("== diameterDTLSDecrypt ==");
        
        /*if (engine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            logger.warn("== diameterDTLSDecrypt DTLS handshake not finnished ==");
            // consider it as ok, if the handshake is still ongoing
            return true;
        }*/
        
        AvpSet avps = message.getAvps();
        
        int avps_size = avps.size();
        
        
        for (int i = 0; i < avps_size; i++) {
            Avp a = avps.getAvpByIndex(i);
            
            //logger.debug("AVP[" + i + "] Code = " + a.getCode());
            
            if (a.getCode() == AVP_DESS_ENCRYPTED && a.isVendorId() && a.getVendorId() == VENDOR_ID) {
                AvpSetImpl _avps;
                try {
                    logger.debug("Diameter Decryption of Grouped Encrypted DTLS AVP");
                    byte[] b = a.getOctetString();
                    byte[] d = b;
                    /*// SPI(version) and TVP(timestamp)decrypt
                    byte[] SPI = {0x00, 0x00, 0x00, 0x00};
                    byte[] TVP = {0x00, 0x00, 0x00, 0x00};
                    byte[] d = null;
                    if (b.length >= SPI.length) {
                        SPI = Arrays.copyOfRange(b, 0, SPI.length);
                        d = Arrays.copyOfRange(b, SPI.length, b.length);
                    } else {
                        d = b;
                    }   // TODO verify SPI*/
                    
                    ByteBuffer decryptedTextBuffer = ByteBuffer.allocate(DTLS_BUFFER_SIZE);
                    boolean res = diameterDTLSDecryptBuffer(engine, ByteBuffer.wrap(d, 0, d.length), decryptedTextBuffer);
                    if (res == false) {
                        logger.warn("diameterDTLSDecrypt: Failed decryption of DTLS data");
                        return false;
                    }
                    
                    
                    if (decryptedTextBuffer.remaining() != 0) {
                        logger.debug("diameterDTLSDecrypt: Successful decryption of DTLS data");
                    }
                        
                    byte[] decryptedText = new byte[decryptedTextBuffer.remaining()];
                    decryptedTextBuffer.get(decryptedText);
                    
                    /*d = decryptedText;
                    
                    if (d.length < 4) {
                        logger.error("diameterDTLSDecrypt: Unable to decrypt data");
                        return false;
                    }
                    
                    // ---- Verify TVP from Security header ----
                    long t = System.currentTimeMillis()/100;    // in 0.1s
                    TVP[0] = (byte) ((t >> 24) & 0xFF);
                    TVP[1] = (byte) ((t >> 16) & 0xFF);
                    TVP[2] = (byte) ((t >>  8) & 0xFF);
                    TVP[3] = (byte) ((t >>  0) & 0xFF);
                    t = 0;
                    for (int j = 0; j < TVP.length; j++) {
                        t =  ((t << 8) + (TVP[j] & 0xff));
                    }

                    TVP[0] = d[0]; TVP[1] = d[1]; TVP[2] = d[2]; TVP[3] = d[3];
                    long t_tvp = 0;
                    for (int j = 0; j < TVP.length; j++) {
                        t_tvp =  ((t_tvp << 8) + (TVP[j] & 0xff));
                    }
                    if (Math.abs(t_tvp-t) > Crypto.diameter_tvp_time_window*10) {
                        return "DIAMETER FW: Blocked in decryption, Wrong timestamp in TVP (received: " + t_tvp + ", current: " + t + ")";
                    }
                    d = Arrays.copyOfRange(d, TVP.length, d.length);*/
                    // ---- End of Verify TVP ----
            
                    //logger.debug("Add AVP Decrypted. Current index = " + i);
                    //AvpImpl avp = new AvpImpl(code, (short) flags, (int) vendor, rawData);
                    //avps.insertAvp(i, ByteBuffer.wrap(cc).order(ByteOrder.BIG_ENDIAN).getInt(), d, false, false);
                    //logger.debug("decryptedText = " + decryptedText.toString());
                    //logger.debug("decryptedText.size = " + decryptedText.length);
                    _avps = (AvpSetImpl)Utils.decodeAvpSet(decryptedText, 0);                   
                    
                    //logger.debug("SIZE = " + _avps.size());
                    
                    /*for (int j = 0; j < _avps.size(); j++) {
                        AvpImpl _a = (AvpImpl)_avps.getAvpByIndex(j);
                        logger.debug("addAVP = " + _a.getCode());
                        avps.insertAvp(i, _a.getCode(), _a.getRawData(), _a.vendorID, _a.isMandatory, _a.isEncrypted);
                    }
                    avps.removeAvpByIndex(i + _avps.size());*/
                    
                    mergeAVPLists(avps, _avps);
                    avps.removeAvp(AVP_DESS_ENCRYPTED, VENDOR_ID);                   
                    
                } catch (IOException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (AvpDataException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                }
  
            }
            
        }
        
        return true;
    }
    /**
     * Remove the protected or non-protected AVPs by iterating all APVs and recursively descending into grouped AVPs
     * @param avps AVP set
     * @param protectedAVPCodes List of protected AVP codes
     * @param removeProtected If set to true, the protected AVPs are removed. If set to false. the non-protected AVPs are removed
     */
    void removeTheAVPs(AvpSet avps,  List<Integer> protectedAVPCodes, boolean removeProtected) throws AvpDataException {
        if (avps == null || protectedAVPCodes == null ) {
            return;
        }
        
        for (int i = 0; i < avps.size(); i++) {
            Avp a = avps.getAvpByIndex(i);
            
            // For grouped AVPs do recursion
            AvpRepresentation avpRep = AvpDictionary.INSTANCE.getAvp(a.getCode(), a.getVendorId());
            if (avpRep != null && avpRep.getType().equals("Grouped")) {
                // removeProtected == true: Remove AVP code if it is in protectedAVPCodes
                // hard delete is done, removing the protected grouped AVPs in every case
                if (removeProtected && protectedAVPCodes.contains(a.getCode())) {
                    avps.removeAvpByIndex(i);
                    i--;
                } else if (removeProtected) {
                    // if the AVP should not be removed, recurs into
                    removeTheAVPs(a.getGrouped(), protectedAVPCodes, removeProtected);
                }
                // removeProtected == false: Remove AVP code if it is not in protectedAVPCodes
                // soft delete is done, preserving non protected grouped AVPs if there are sub AVPs
                if (!removeProtected && !protectedAVPCodes.contains(a.getCode())){
                    
                    // while removing non protected AVP also remove sub AVP entries which are also non protected
                    removeTheAVPs(a.getGrouped(), protectedAVPCodes, removeProtected);

                    // Remove empty grouped AVPs only
                    if (a.getGrouped().size() == 0) {
                        avps.removeAvpByIndex(i);
                        i--;
                    }
                } else if (!removeProtected) {
                    // if the AVP should not be removed (it is protected), don't recurs into
                    // do nothing
                }
            }
            // Non grouped AVPs
            else {
                // removeProtected == true: Remove AVP code if it is in protectedAVPCodes
                if (removeProtected && protectedAVPCodes.contains(a.getCode())) {
                    avps.removeAvpByIndex(i);
                    i--;
                } 
                // removeProtected == true: Remove AVP code if it is not in protectedAVPCodes
                else if (!removeProtected && !protectedAVPCodes.contains(a.getCode())){
                    avps.removeAvpByIndex(i);
                    i--;
                }
            }
        }
    }
    
    /**
     * Merge 2 AVP Sets by considering also grouped AVPs. Remove the dest AVPs if the same AVP code exist in source AVP set on same hierarchy level.
     * @param avps Dest AVP set
     * @param _avps Source AVP set which will be added into Dest AVP set
     */
    void mergeAVPLists(AvpSet avps, AvpSet _avps) throws AvpDataException {
        if (avps == null || _avps == null ) {
            return;
        }
        
        for (int i = 0; i < _avps.size(); i++) {
            Avp _a = _avps.getAvpByIndex(i);
            
            // Simple Add AVP if such AVP does not exist in dest AVP set
            Avp a = avps.getAvp(_a.getCode());
            if (a == null) {
                avps.addAvp(_a.getCode(), _a.getRawData(), _a.getVendorId(), _a.isMandatory(), _a.isEncrypted());
            }
            // If the AVP exists in dest AVP set
            else {
                // For grouped AVPs do recursion
                AvpRepresentation avpRep = AvpDictionary.INSTANCE.getAvp(_a.getCode(), _a.getVendorId());
                if (avpRep != null && avpRep.getType().equals("Grouped")) {
                    mergeAVPLists(a.getGrouped(), _a.getGrouped());
                }
                // For basic AVPs, do merge with replace
                else {
                    // Remove the dest AVPs if the same AVP code exist in source AVP set on same hierarchy level
                    avps.removeAvp(a.getCode());
                    
                    // Add AVP
                    avps.addAvp(_a.getCode(), _a.getRawData(), _a.getVendorId(), _a.isMandatory(), _a.isEncrypted());
                }
            }
        }
    }
    
}
