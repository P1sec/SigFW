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

import static diameterfw.DiameterFirewallConfig.keyFactory;
import diameterfw.connectorIDS.ConnectorIDS;
import diameterfw.connectorIDS.ConnectorIDSModuleRest;
import diameterfw.connectorMThreat.ConnectorMThreat;
import diameterfw.connectorMThreat.ConnectorMThreatModuleRest;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URISyntaxException;
import java.net.UnknownServiceException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
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
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
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
import org.jdiameter.api.ApplicationId;
import org.jdiameter.api.Avp;
import org.jdiameter.api.AvpDataException;
import org.jdiameter.api.AvpSet;
import org.jdiameter.api.Message;
import org.jdiameter.api.ResultCode;
import org.jdiameter.api.Session;
import org.jdiameter.api.SessionFactory;
import org.jdiameter.api.Stack;
import org.jdiameter.api.URI;
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
import org.mobicents.protocols.sctp.AssociationImpl;
import org.mobicents.protocols.sctp.ManagementImpl;

/**
 * @author Martin Kacer
 * 
 */
public class DiameterFirewall implements /*NetworkReqListener,*/ ManagementEventListener, ServerListener, AssociationListener {
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


    // ////////////////////////////////////////
    // Objects which will be used in action //
    // ////////////////////////////////////////
    private Session session;
    private int toReceiveIndex = 0;
    private boolean finished = false;


    // SCTP
    private static ManagementImpl sctpManagement;

    // Diameter
    protected final MessageParser parser = new MessageParser();
    
    static private String configName = "sigfw.json";

    // API
    private static org.eclipse.jetty.server.Server jettyServer;
    
    // IDS API
    private static ConnectorIDS connectorIDS = null;
    
    // mThreat API
    static ConcurrentLinkedDeque<String> mThreat_alerts = new ConcurrentLinkedDeque<String>();
    private static ConnectorMThreat connectorMThreat = null;
    
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
    
    // Diameter sessions
    // TODO consider additng Diameter Host into Key
    // Used to correlate Diameter Answers with Requests, to learn the Dest-Realm for the answer
    // Key: AppID + ":" + "CommandCode" + ":" + Dest_realm + ":" + msg.getEndToEndIdentifier() + ":" + msg.getHopByHopIdentifier())
    // Value: Origin-Realm from first message detected (Request)
    private static Map<String, String> diameter_sessions = ExpiringMap.builder()
                                                .expiration(10, TimeUnit.SECONDS)
                                                .build();
    
    // Encryption Autodiscovery
    // TODO
    
    // Diameter signature and decryption time window used for TVP
    private final static long diameter_tvp_time_window = 30;  // in seconds
    
    static Random randomGenerator = new Random();

    static final private String persistDir = "XmlDiameterFirewall";
    
    static final private int AVP_ENCRYPTED = 1100;
    static final private int AVP_ENCRYPTED_GROUPED = 1101;
    static final private int AVP_SIGNATURE = 1000;
    
    static final private int CC_AUTO_ENCRYPTION = 999;
    static final private int AVP_AUTO_ENCRYPTION_VERION = 1101;
    static final private int AVP_AUTO_ENCRYPTION_REALM = 1102;
    static final private int AVP_AUTO_ENCRYPTION_PUBLIC_KEY = 1103;

    private void initSCTP(IpChannelType ipChannelType) throws Exception {
        logger.debug("Initializing SCTP Stack ....");
        this.sctpManagement = new ManagementImpl(
                (String)DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_management_name")
        );
        this.sctpManagement.setSingleThread(false);

        // TODO no persistent XMLs
        // will cause FileNotFoundException, but currently there is no method to properly disable it
        // If the XMLs are present the SCTP server is started twice and there is problem with reconnections
        this.sctpManagement.setPersistDir(persistDir);

        this.sctpManagement.start();
        this.sctpManagement.setConnectDelay(10000);
        this.sctpManagement.setMaxIOErrors(30);
        this.sctpManagement.removeAllResourses();
        this.sctpManagement.addManagementEventListener(this);
        this.sctpManagement.setServerListener(this);


        // 1. Create SCTP Server
        List<Map<String, Object>> sctp_server = DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_server");
        for (int i = 0; i < sctp_server.size(); i++) {
            this.sctpManagement.addServer(
                    (String)sctp_server.get(i).get("server_name"),
                    (String)sctp_server.get(i).get("host_address"),
                    Integer.parseInt((String)sctp_server.get(i).get("port")),
                    ipChannelType, null
            );
        }

        // 2. Create SCTP Server Association
        List<Map<String, Object>> sctp_server_association = DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_server_association");
        for (int i = 0; i < sctp_server_association.size(); i++) {
           AssociationImpl serverAssociation = this.sctpManagement.addServerAssociation(
                    (String)sctp_server_association.get(i).get("peer_address"),
                    Integer.parseInt((String)sctp_server_association.get(i).get("peer_port")),
                    (String)sctp_server_association.get(i).get("server_name"),
                    (String)sctp_server_association.get(i).get("assoc_name"),
                    ipChannelType
            );
            serverAssociation.setAssociationListener(this);
            this.sctpManagement.startAssociation((String)sctp_server_association.get(i).get("assoc_name"));
        }


        // 3. Create SCTP Client Association
        List<Map<String, Object>> sctp_association = DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_association");
        for (int i = 0; i < sctp_association.size(); i++) {
            AssociationImpl clientAssociation = this.sctpManagement.addAssociation(
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

    private void initStack(IpChannelType ipChannelType) throws Exception {
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
        
        
        logger.setLevel(org.apache.log4j.Level.DEBUG);

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
     * Method to encrypt Diameter message
     * 
     * @param message Diameter message which will be encrypted
     * @param publicKey Public Key used for message encryption
     */
    public void diameterEncrypt(Message message, PublicKey publicKey) throws InvalidKeyException {
        
        //logger.debug("== diameterEncrypt ==");
        AvpSet avps = message.getAvps();
        
        int avps_size = avps.size();
        
        for (int i = 0; i < avps_size; i++) {
            Avp a = avps.getAvpByIndex(i);
            
            //logger.debug("AVP[" + i + "] Code = " + a.getCode());
            
            if (
                    a.getCode() != Avp.ORIGIN_HOST &&
                    a.getCode() != Avp.ORIGIN_REALM &&
                    a.getCode() != Avp.DESTINATION_HOST &&
                    a.getCode() != Avp.DESTINATION_REALM &&
                    a.getCode() != Avp.SESSION_ID &&
                    a.getCode() != Avp.ROUTE_RECORD &&
                    a.getCode() != AVP_ENCRYPTED &&
                    a.getCode() != AVP_ENCRYPTED_GROUPED
                ) {
                
                try {
                    //byte[] d = a.getRawData();
                    byte [] d = this.encodeAvp(a);
                    
                    // SPI(version) and TVP(timestamp)
                    byte[] SPI = {0x00, 0x00, 0x00, 0x00};  // TODO
                    byte[] TVP = {0x00, 0x00, 0x00, 0x00};

                    long t = System.currentTimeMillis()/100;    // in 0.1s
                    TVP[0] = (byte) ((t >> 24) & 0xFF);
                    TVP[1] = (byte) ((t >> 16) & 0xFF);
                    TVP[2] = (byte) ((t >>  8) & 0xFF);
                    TVP[3] = (byte) ((t >>  0) & 0xFF);

                    //DiameterFirewallConfig.cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                    //byte[] cipherText = DiameterFirewallConfig.cipher.doFinal(b);
                    
                    RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
                    DiameterFirewallConfig.cipher.init(Cipher.ENCRYPT_MODE, publicKey);

                    int keyLength = rsaPublicKey.getModulus().bitLength() / 8;

                    byte[][] datas = splitByteArray(d, keyLength - 11 - 4);
                    byte[] cipherText = null;
                    for (byte[] b : datas) {
                        cipherText = concatByteArray(cipherText, DiameterFirewallConfig.cipher.doFinal(concatByteArray(TVP, b)));
                    }
                    
                    cipherText = concatByteArray(SPI, cipherText);
                    
                    //logger.debug("Add AVP Encrypted. Current index = " + i);
                    avps.insertAvp(i, AVP_ENCRYPTED, cipherText, finished, finished);
                    
                    avps.removeAvpByIndex(i + 1);
                    
                } catch (IllegalBlockSizeException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (BadPaddingException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }
    
        /**
     * Method to encrypt Diameter message v2
     * 
     * @param message Diameter message which will be encrypted
     * @param publicKey Public Key used for message encryption
     */
    public void diameterEncrypt_v2(Message message, PublicKey publicKey) throws InvalidKeyException {
        
        //logger.debug("== diameterEncrypt_v2 ==");
        AvpSet avps = message.getAvps();
        
        AvpSet erAvp = avps.addGroupedAvp(AVP_ENCRYPTED_GROUPED);
        
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
                    a.getCode() != AVP_ENCRYPTED &&
                    a.getCode() != AVP_ENCRYPTED_GROUPED
                ) {
                    erAvp.addAvp(a);
                    avps.removeAvpByIndex(i);
                    i--;
            }
        }
        
        try {
            //byte[] d = a.getRawData();
            byte [] d = encodeAvpSet(erAvp);
            
            logger.debug("avps.size = " + erAvp.size());
            logger.debug("plainText = " + d.toString());
            logger.debug("plainText.size = " + d.length);

            // SPI(version) and TVP(timestamp)
            byte[] SPI = {0x00, 0x00, 0x00, 0x00};  // TODO
            byte[] TVP = {0x00, 0x00, 0x00, 0x00};

            long t = System.currentTimeMillis()/100;    // in 0.1s
            TVP[0] = (byte) ((t >> 24) & 0xFF);
            TVP[1] = (byte) ((t >> 16) & 0xFF);
            TVP[2] = (byte) ((t >>  8) & 0xFF);
            TVP[3] = (byte) ((t >>  0) & 0xFF);

            //DiameterFirewallConfig.cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            //byte[] cipherText = DiameterFirewallConfig.cipher.doFinal(b);

            RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
            DiameterFirewallConfig.cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            int keyLength = rsaPublicKey.getModulus().bitLength() / 8;

            byte[][] datas = splitByteArray(d, keyLength - 11 - 4);
            byte[] cipherText = null;
            for (byte[] b : datas) {
                cipherText = concatByteArray(cipherText, DiameterFirewallConfig.cipher.doFinal(concatByteArray(TVP, b)));
            }

            cipherText = concatByteArray(SPI, cipherText);

            //logger.debug("Add AVP Grouped Encrypted. Current index");
            avps.removeAvp(AVP_ENCRYPTED_GROUPED);
            avps.addAvp(AVP_ENCRYPTED_GROUPED, cipherText, finished, finished);

        } catch (IllegalBlockSizeException ex) {
            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Method to decrypt Diameter message
     * 
     * @param message Diameter message which will be decrypted
     * @param keyPair Key Pair used for message encryption
     * @return result, empty string if successful, otherwise error message
     */
    public String diameterDecrypt(Message message, KeyPair keyPair) {
        //logger.debug("== diameterDecrypt ==");
        AvpSet avps = message.getAvps();
        
        int avps_size = avps.size();
        
        for (int i = 0; i < avps_size; i++) {
            Avp a = avps.getAvpByIndex(i);
            
            //logger.debug("AVP[" + i + "] Code = " + a.getCode());
            
            if (a.getCode() == AVP_ENCRYPTED) {
                logger.debug("Diameter Decryption of Encrypted AVP");
                    
                try {
                    byte[] b = a.getOctetString();
                    
                    // SPI(version) and TVP(timestamp)
                    byte[] SPI = {0x00, 0x00, 0x00, 0x00};
                    byte[] TVP = {0x00, 0x00, 0x00, 0x00};

                    byte[] d = null; 
                    if (b.length >= SPI.length) {
                        SPI = Arrays.copyOfRange(b, 0, SPI.length);
                        d = Arrays.copyOfRange(b, SPI.length, b.length);
                    } else {
                        d = b;
                    }

                    // TODO verify SPI

                    PrivateKey privateKey = keyPair.getPrivate();
                    DiameterFirewallConfig.cipher.init(Cipher.DECRYPT_MODE, privateKey);

                    RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
                    int keyLength = rsaPublicKey.getModulus().bitLength() / 8;
                    
                    byte[][] datas = splitByteArray(d, keyLength/* - 11*/);
                    byte[] decryptedText = null;
                    for (byte[] _b : datas) {
                        d = DiameterFirewallConfig.cipher.doFinal(_b);
                        
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
                        if (Math.abs(t_tvp-t) > diameter_tvp_time_window*10) {
                            return "DIAMETER FW: Blocked in decryption, Wrong timestamp in TVP (received: " + t_tvp + ", current: " + t + ")";
                        }
                        d = Arrays.copyOfRange(d, TVP.length, d.length);
                        // ---- End of Verify TVP ----
                        
                        
                        decryptedText = concatByteArray(decryptedText, d);
                    }
                   
                    
                    //logger.debug("Add AVP Decrypted. Current index = " + i);
                    //AvpImpl avp = new AvpImpl(code, (short) flags, (int) vendor, rawData);
                    
                    //avps.insertAvp(i, ByteBuffer.wrap(cc).order(ByteOrder.BIG_ENDIAN).getInt(), d, finished, finished);
                    
                    AvpImpl _a = (AvpImpl)decodeAvp(decryptedText);
                    avps.insertAvp(i, _a.getCode(), _a.getRawData(), _a.vendorID, _a.isMandatory, finished);
                    
                    avps.removeAvpByIndex(i + 1);
                    
                } catch (InvalidKeyException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IllegalBlockSizeException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (BadPaddingException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (AvpDataException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                }
            } else if (a.getCode() == AVP_ENCRYPTED_GROUPED) {
                logger.debug("Diameter Decryption of Grouped Encrypted AVP");
                    
                try {
                    byte[] b = a.getOctetString();
                    
                    // SPI(version) and TVP(timestamp)
                    byte[] SPI = {0x00, 0x00, 0x00, 0x00};
                    byte[] TVP = {0x00, 0x00, 0x00, 0x00};

                    byte[] d = null; 
                    if (b.length >= SPI.length) {
                        SPI = Arrays.copyOfRange(b, 0, SPI.length);
                        d = Arrays.copyOfRange(b, SPI.length, b.length);
                    } else {
                        d = b;
                    }

                    // TODO verify SPI

                    PrivateKey privateKey = keyPair.getPrivate();
                    DiameterFirewallConfig.cipher.init(Cipher.DECRYPT_MODE, privateKey);

                    RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
                    int keyLength = rsaPublicKey.getModulus().bitLength() / 8;
                    
                    byte[][] datas = splitByteArray(d, keyLength/* - 11*/);
                    byte[] decryptedText = null;
                    for (byte[] _b : datas) {
                        d = DiameterFirewallConfig.cipher.doFinal(_b);
                        
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
                        if (Math.abs(t_tvp-t) > diameter_tvp_time_window*10) {
                            return "DIAMETER FW: Blocked in decryption, Wrong timestamp in TVP (received: " + t_tvp + ", current: " + t + ")";
                        }
                        d = Arrays.copyOfRange(d, TVP.length, d.length);
                        // ---- End of Verify TVP ----
                        
                        
                        decryptedText = concatByteArray(decryptedText, d);
                    }
                   
                    
                    //logger.debug("Add AVP Decrypted. Current index = " + i);
                    //AvpImpl avp = new AvpImpl(code, (short) flags, (int) vendor, rawData);
                    
                    //avps.insertAvp(i, ByteBuffer.wrap(cc).order(ByteOrder.BIG_ENDIAN).getInt(), d, finished, finished);
                    
                    //logger.debug("decryptedText = " + decryptedText.toString());
                    //logger.debug("decryptedText.size = " + decryptedText.length);
                    AvpSetImpl _avps = (AvpSetImpl)decodeAvpSet(decryptedText, 0);
                    
                    //logger.debug("SIZE = " + _avps.size());
                    
                    for (int j = 0; j < _avps.size(); j++) {
                        AvpImpl _a = (AvpImpl)_avps.getAvpByIndex(j);
                        //logger.debug("addAVP = " + _a.getCode());
                        avps.insertAvp(i, _a.getCode(), _a.getRawData(), _a.vendorID, _a.isMandatory, finished);
                    }
                    avps.removeAvpByIndex(i + _avps.size());
                    
                } catch (InvalidKeyException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IllegalBlockSizeException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (BadPaddingException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (AvpDataException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        
        return "";
    }
    
    /**
     * Method to sign Diameter message
     * 
     * @param message Diameter message which will be signed
     * @param keyPair KeyPair used to sign message
     */
    public void diameterSign(Message message, KeyPair keyPair) {
        //logger.debug("Message Sign = " + message.getAvps().toString());
        
        if (keyPair != null) {
            PrivateKey privateKey = keyPair.getPrivate();
            if(privateKey != null) {
        
                AvpSet avps = message.getAvps();

                boolean signed = false;
                for (int i = 0; i < avps.size(); i++) {
                    Avp a = avps.getAvpByIndex(i);
                    if (a.getCode() == AVP_SIGNATURE) {
                        signed = true;
                        break;
                    }
                }
                
                if (!signed) {
                    // Reserved (currently not used) - Signature Version
                    // TODO
                    byte[] VER = {0x00, 0x00, 0x00, 0x01};
                    
                    // TVP
                    byte[] TVP = {0x00, 0x00, 0x00, 0x00};

                    long t = System.currentTimeMillis()/100;    // in 0.1s
                    TVP[0] = (byte) ((t >> 24) & 0xFF);
                    TVP[1] = (byte) ((t >> 16) & 0xFF);
                    TVP[2] = (byte) ((t >>  8) & 0xFF);
                    TVP[3] = (byte) ((t >>  0) & 0xFF);

                    long t_tvp = 0;
                    for (int j = 0; j < TVP.length; j++) {
                        t_tvp =  ((t_tvp << 8) + (TVP[j] & 0xff));
                    }
                    
                    // Signature
                    try {
                        DiameterFirewallConfig.signature.initSign(privateKey);

                        String dataToSign = message.getApplicationId() + ":" + message.getCommandCode() + ":" + message.getEndToEndIdentifier() + ":" + t_tvp;
                        
                        // jDiameter AVPs are not ordered, and the order could be changed by DRAs in IPX, so order AVPs by sorting base64 strings
                        List<String> strings = new ArrayList<String>();
                        for (int i = 0; i < avps.size(); i++) {
                            Avp a = avps.getAvpByIndex(i);
                            if (a.getCode() != Avp.RECORD_ROUTE) {
                                strings.add(a.getCode() + "|" + Base64.getEncoder().encodeToString(a.getRawData()));
                            }
                        }
                        Collections.sort(strings);
                        for (String s : strings) {
                             dataToSign += ":" + s;
                        }
                        
                        /*for (int i = 0; i < avps.size(); i++) {
                            Avp a = avps.getAvpByIndex(i);
                            if (a.getCode() != Avp.RECORD_ROUTE) {
                                dataToSign += ":" + Base64.getEncoder().encodeToString(a.getRawData());
                            }
                        }*/
                        
                        DiameterFirewallConfig.signature.update(dataToSign.getBytes());
                        byte[] signatureBytes = DiameterFirewallConfig.signature.sign();
                        logger.debug("Adding Diameter Signed Data: " + dataToSign);
                        logger.debug("Adding Diameter Signature: " + Base64.getEncoder().encodeToString(signatureBytes));

                        avps.addAvp(AVP_SIGNATURE, concatByteArray(VER, concatByteArray(TVP, signatureBytes)));

                    } catch (InvalidKeyException ex) {
                        java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (SignatureException ex) {
                        java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }          
            }
        }
    }
    
    /**
     * Method to verify the Diameter message signature
     * 
     * 
     * @param message Diameter message which will be verified
     * @param publicKey Public Key used to verify message signature
     * @return result, empty string if successful, otherwise error message
     */
    public String diameterVerify(Message message, PublicKey publicKey) {
        //logger.debug("Message Verify = " + message.getAvps().toString());
        
        if (publicKey == null) {
            return "";
        }
        
        List<Integer> signed_index = new ArrayList<Integer>();
        
        AvpSet avps = message.getAvps();

        for (int i = 0; i < avps.size(); i++) {
            Avp a = avps.getAvpByIndex(i);
            if (a.getCode() == AVP_SIGNATURE) {
                signed_index.add(i);
            }
        } 
        
        if (signed_index.size() > 0) {
            try {
                // read signature component
                Avp a = avps.getAvpByIndex(signed_index.get(0));
                byte[] ad;

                ad = a.getOctetString();

                byte[] signatureBytes = null;
                long t_tvp = 0;
                byte[] TVP = {0x00, 0x00, 0x00, 0x00};
                
                // Reserved (currently not used) - Signature Version
                // TODO
                int pos = 0;
                byte[] VER = {0x00, 0x00, 0x00, 0x01};
                
                pos = 4;
                // TVP
                if (ad != null && ad.length > TVP.length + pos) {
                    // ---- Verify TVP from Security header ----
                    long t = System.currentTimeMillis()/100;    // in 0.1s
                    TVP[0] = (byte) ((t >> 24) & 0xFF);
                    TVP[1] = (byte) ((t >> 16) & 0xFF);
                    TVP[2] = (byte) ((t >>  8) & 0xFF);
                    TVP[3] = (byte) ((t >>  0) & 0xFF);
                    t = 0;
                    for (int i = 0; i < TVP.length; i++) {
                        t =  ((t << 8) + (TVP[i] & 0xff));
                    }

                    for (int i = 0; i < TVP.length; i++) {
                        t_tvp =  ((t_tvp << 8) + (ad[i + pos] & 0xff));
                    }
                    
                    if (Math.abs(t_tvp-t) > diameter_tvp_time_window*10) {
                        return "DIAMETER FW: DIAMETER verify signature. Wrong timestamp in TVP (received: " + t_tvp + ", current: " + t + ")";
                    }
                    // ---- End of Verify TVP ----
                }

            
                // Signature
                if (ad != null) {
                    signatureBytes = Arrays.copyOfRange(ad, TVP.length + pos, ad.length);
                }

                // remove all signature components
                for (int i = 0; i < signed_index.size(); i++) {
                    avps.removeAvpByIndex(signed_index.get(i));
                }

                // verify signature 
                String dataToSign = message.getApplicationId() + ":" + message.getCommandCode() + ":" + message.getEndToEndIdentifier() + ":" + t_tvp;
                
                // jDiameter AVPs are not ordered, so order AVPs by sorting base64 strings
                List<String> strings = new ArrayList<String>();
                for (int i = 0; i < avps.size(); i++) {
                    a = avps.getAvpByIndex(i);
                    if (a.getCode() != Avp.RECORD_ROUTE) {
                        strings.add(a.getCode() + "|" + Base64.getEncoder().encodeToString(a.getRawData()));
                    }
                }
                Collections.sort(strings);
                for (String s : strings) {
                     dataToSign += ":" + s;
                }

                /*for (int i = 0; i < avps.size(); i++) {
                    Avp a = avps.getAvpByIndex(i);
                    if (a.getCode() != Avp.RECORD_ROUTE) {
                        dataToSign += ":" + Base64.getEncoder().encodeToString(a.getRawData());
                    }
                }*/
                
                DiameterFirewallConfig.signature.initVerify(publicKey);
                DiameterFirewallConfig.signature.update(dataToSign.getBytes());
                if (signatureBytes != null && DiameterFirewallConfig.signature.verify(signatureBytes)) {
                    return "";
                }

            } catch (InvalidKeyException ex) {
                java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SignatureException ex) {
                java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
            } catch (AvpDataException ex) {
                java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        return "DIAMETER FW: Wrong DIAMETER signature";
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
        try {
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
            
            List<Map<String, Object>> sctp_server_association = DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_server_association");
            List<Map<String, Object>> sctp_association = DiameterFirewallConfig.get("$.sigfw_configuration.sctp.sctp_association");


            ByteBuffer byteBuffer;
            byteBuffer = parser.encodeMessage((IMessage)message);
        
            PayloadData payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, payloadProtocolId, streamNumber);

            // Server associations
            for (int i = 0; i < sctp_server_association.size(); i++) {
                if (origin_asctn.getName().equals((String)sctp_server_association.get(i).get("assoc_name"))) {
                    try {
                        // TODO round robin
                        if (forward_indicator) {
                            this.sctpManagement.getAssociation((String)sctp_association.get(0).get("assoc_name")).send(payloadData);
                        } else {
                            this.sctpManagement.getAssociation((String)sctp_server_association.get(0).get("assoc_name")).send(payloadData);
                        }
                    } catch (Exception ex) {
                        java.util.logging.Logger.getLogger(DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
            // Client associations
            for (int i = 0; i < sctp_association.size(); i++) {
                if (origin_asctn.getName().equals((String)sctp_association.get(i).get("assoc_name"))) {
                    try {
                        // TODO round robin
                        if (forward_indicator) {
                            this.sctpManagement.getAssociation((String)sctp_server_association.get(0).get("assoc_name")).send(payloadData);
                        } else {
                            this.sctpManagement.getAssociation((String)sctp_association.get(0).get("assoc_name")).send(payloadData);
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
    

    public void onPayload(Association asctn, PayloadData pd) {
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
            Message msg = this.parser.createMessage(buf);
            
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
                String session_id = ai + ":" + cc + ":" + dest_realm + ":" + msg.getEndToEndIdentifier() + ":" + msg.getHopByHopIdentifier();
                diameter_sessions.put(session_id, orig_realm);
            }
            // ------------------------------------------
            
            // ----------- Pass CER, DWR, DPR -----------
            if (cc == 257 || cc == 280 || cc == 282) {
                sendDiameterMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, true, lua_hmap);
                return;
            }
            // ------------------------------------------
            
            // ---------- Diameter decryption -----------
            // Diameter Decryption
            // Requests containing Dest-Realm
            if (!dest_realm.equals("") && msg.isRequest()) { 
                if (DiameterFirewallConfig.destination_realm_decryption.containsKey(dest_realm)) {
                    KeyPair keyPair = DiameterFirewallConfig.destination_realm_decryption.get(dest_realm);
                    
                    // decrypt
                    String r = diameterDecrypt(msg, keyPair);
                    if (!r.equals("")) {
                        firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, r, lua_hmap);
                        return;
                    }
                }
            }
            // Answers without Dest-Realm, but seen previously Request
            else if (!msg.isRequest()) {
                String _dest_realm = "";
                String session_id = ai + ":" + cc + ":" + orig_realm + ":" + msg.getEndToEndIdentifier() + ":" + msg.getHopByHopIdentifier();
                if (diameter_sessions.containsKey(session_id)) {
                    _dest_realm = diameter_sessions.get(session_id);
                }
                if (DiameterFirewallConfig.destination_realm_decryption.containsKey(_dest_realm)) {
                    KeyPair keyPair = DiameterFirewallConfig.destination_realm_decryption.get(_dest_realm);
                    logger.debug("Diameter Decryption of Answer for Destination Realm = " + _dest_realm);

                    // decrypt
                    String r = diameterDecrypt(msg, keyPair);
                    if (!r.equals("")) {
                        firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, r, lua_hmap);
                        return;
                    }
                    
                    diameter_sessions.remove(session_id);
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
                if(connectorIDS.evalDiameterMessage(DatatypeConverter.printHexBinary(pd.getData())) == false) {
                    firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, "DIAMETER FW: Blocked by IDS " + i, lua_hmap);
                    return;
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
                        
                        // Reserved (currently not used) - Version
                        // TODO
                        answer.getAvps().addAvp(AVP_AUTO_ENCRYPTION_VERION, "v1".getBytes());

                        // Realm
                        answer.getAvps().addAvp(AVP_AUTO_ENCRYPTION_REALM, dest_realm.getBytes());

                        // Public key
                        answer.getAvps().addAvp(AVP_AUTO_ENCRYPTION_PUBLIC_KEY,myKeyPair.getPublic().getEncoded());
                        
                        logger.info("============ Encryption Autodiscovery Sending Result ============ ");
                        
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
                    
                    // Reserved (currently not used) - Public key type
                    // TODO
                    
                    // Realm prefix
                    String realm = "";
                    if (msg.getAvps().getAvp(AVP_AUTO_ENCRYPTION_REALM) != null) {
                        byte[] d2 = msg.getAvps().getAvp(AVP_AUTO_ENCRYPTION_REALM).getOctetString();
                        realm = new String(d2);
                    }
                    
                    // Public key
                    if (msg.getAvps().getAvp(AVP_AUTO_ENCRYPTION_PUBLIC_KEY) != null) {
                        byte[] d3 = msg.getAvps().getAvp(AVP_AUTO_ENCRYPTION_PUBLIC_KEY).getOctetString();
                        // TODO add method into config to add public key
                        byte[] publicKeyBytes =  d3;
                        try {
                            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                            PublicKey publicKey;
                            publicKey = keyFactory.generatePublic(pubKeySpec);
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
            
            // --------------- Diameter signature ---------------
            // Sign only Requests containing Orig-Realm
            if (!orig_realm.equals("") && msg.isRequest()) {
                // ------------- Diameter verify --------------
                if (DiameterFirewallConfig.origin_realm_verify.containsKey(orig_realm)) {
                    PublicKey publicKey = DiameterFirewallConfig.origin_realm_verify.get(orig_realm);
                    String r = diameterVerify(msg, publicKey);
                    if (!r.equals("")) {
                        firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, r, lua_hmap);
                        return;
                    }
                }
                // --------------------------------------------
                // ------------- Diameter signing -------------
                if (DiameterFirewallConfig.origin_realm_signing.containsKey(orig_realm)) {
                    KeyPair keyPair = DiameterFirewallConfig.origin_realm_signing.get(orig_realm);
                    diameterSign(msg, keyPair);
                }
                // --------------------------------------------
            }
            // ------------------------------------------
            
        
            // ---------- Diameter encryption -----------
            String session_id = ai + ":" +  cc + ":" +  orig_realm + ":" + msg.getEndToEndIdentifier() + ":" + msg.getHopByHopIdentifier();

            // Requests containing Dest-Realm
            if (!dest_realm.equals("") && msg.isRequest() && DiameterFirewallConfig.destination_realm_encryption.containsKey(dest_realm)) { 
                PublicKey publicKey = DiameterFirewallConfig.destination_realm_encryption.get(dest_realm);
                logger.debug("Diameter Encryption of Request for Destination Realm = " + dest_realm);

                // encrypt
                diameterEncrypt(msg, publicKey);
                // TODO change to v2 to use encrypted grouped AVP
                // diameterEncrypt_v2(msg, publicKey);
            }
            // Answers without Dest-Realm, but seen previous Request
            else if (!msg.isRequest()
                    && diameter_sessions.containsKey(session_id) 
                    && DiameterFirewallConfig.destination_realm_encryption.containsKey(diameter_sessions.get(session_id))
              ) {
                String _dest_realm = diameter_sessions.get(session_id);

                PublicKey publicKey = DiameterFirewallConfig.destination_realm_encryption.get(_dest_realm);
                logger.debug("Diameter Encryption of Answer for Destination Realm = " + _dest_realm);

                // encrypt
                diameterEncrypt(msg, publicKey);
                // TODO change to v2 to use encrypted grouped AVP
                // diameterEncrypt_v2(msg, publicKey);

                diameter_sessions.remove(session_id);

            }
            // ------------ Encryption Autodiscovery ------------ 
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

                if (!encryption_autodiscovery_sessions_reverse.containsKey(_dest_realm)) {

                    IMessage message = parser.createEmptyMessage((IMessage)msg, CC_AUTO_ENCRYPTION);

                    if(!msg.isRequest()) {
                        message.setRequest(true);
                        // TODO usa raw AVP encoding, because aaa:// is added by jDiameter
                        message.getAvps().addAvp(Avp.DESTINATION_REALM, _dest_realm, true, false, true);
                    }

                    message.setHeaderApplicationId(16777251);

                    avp = msg.getAvps().getAvp(Avp.ORIGIN_REALM);
                    if (avp != null) {
                        message.getAvps().addAvp(avp);
                    }

                    // --------- Add also Diameter signature ------------
                    if (DiameterFirewallConfig.origin_realm_signing.containsKey(orig_realm)) {
                        KeyPair keyPair = DiameterFirewallConfig.origin_realm_signing.get(orig_realm);
                        diameterSign(message, keyPair);
                    }
                    // --------------------------------------------------

                    logger.info("============ Sending Autodiscovery Request ============ ");

                    // Workaround. E2E ID long value should be clamp to 32bit before use. It is clamped in proto encoding. 
                    // See jDiamter MessageParser.java, Line 111. long endToEndId = ((long) in.readInt() << 32) >>> 32;
                    long e2e_id = ((long) message.getEndToEndIdentifier() << 32) >>> 32;
                    message.setEndToEndIdentifier(e2e_id);
                    //

                    sendDiameterMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), message, true, lua_hmap);


                    logger.debug("encryption_autodiscovery_sessions.put " + message.getEndToEndIdentifier() + " " + _dest_realm);
                    encryption_autodiscovery_sessions.put(message.getEndToEndIdentifier(), _dest_realm);
                    logger.debug("encryption_autodiscovery_sessions_reverse.put " + _dest_realm + " " + message.getEndToEndIdentifier());
                    encryption_autodiscovery_sessions_reverse.put(_dest_realm, message.getEndToEndIdentifier());
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
    }

    public void onCommunicationUp(Association asctn, int i, int i1) {
        logger.debug("[[[[[[[[[[    onCommunicationUp      ]]]]]]]]]]");
    }

    public void onCommunicationShutdown(Association asctn) {
        logger.debug("[[[[[[[[[[    onCommunicationShutdown      ]]]]]]]]]]");
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
     * Method to split byte array 
     * 
     * @param bytes original byte array
     * @param chunkSize chunk size
     * @return two dimensional byte array
     */
    private byte[][] splitByteArray(byte[] bytes, int chunkSize) {
        int len = bytes.length;
        int counter = 0;

        int size = ((bytes.length - 1) / chunkSize) + 1;
        byte[][] newArray = new byte[size][]; 

        for (int i = 0; i < len - chunkSize + 1; i += chunkSize) {
            newArray[counter++] = Arrays.copyOfRange(bytes, i, i + chunkSize);
        }

        if (len % chunkSize != 0) {
            newArray[counter] = Arrays.copyOfRange(bytes, len - len % chunkSize, len);
        }
        
        return newArray;
    }
    
    /**
     * Concatenate two byte arrays
     * 
     * @param bytes first byte array
     * @param chunkSize second byte array
     * @return concatenated byte array
     */
    private byte[] concatByteArray(byte[] a, byte[] b) {
        if (a == null) { 
            return b;
        }
        if (b == null) {
            return a;
        }
        
        byte[] r = new byte[a.length + b.length];

        System.arraycopy(a, 0, r, 0, a.length);

        System.arraycopy(b, 0, r, a.length, b.length);
        
        return r;
    }
    
    // workaround because in jDiameter AvpImpl, AvpSetImpl is not public
    // TODO submit to jDiameter to make AvpImpl, AvpSetImpl public
    private static final int INT32_SIZE = 4;
    
    public byte[] encodeAvp(Avp avp) {
        try {
            int payloadSize = avp.getRaw().length;
            boolean hasVendorId = avp.getVendorId() != 0;
            int origLength = payloadSize + 8 + (hasVendorId ? 4 : 0);
            int tmp = payloadSize % 4;
            int paddingSize = tmp > 0 ? (4 - tmp) : 0;

            byte[] bCode = this.int32ToBytes(avp.getCode());
            int flags = (byte) ((hasVendorId ? 0x80 : 0)
                    | (avp.isMandatory() ? 0x40 : 0) | (avp.isEncrypted() ? 0x20 : 0));
            byte[] bFlags = this.int32ToBytes(((flags << 24) & 0xFF000000) + origLength);
            byte[] bVendor = hasVendorId ? int32ToBytes((int) avp.getVendorId()) : new byte[0];
            return this.concat(origLength + paddingSize, bCode, bFlags, bVendor, avp.getRaw());
        } catch (Exception e) {
            logger.debug("Error during encode avp", e);
            return new byte[0];
        }
    }
    
    
    protected class DynamicByteArray {

        private byte[] array;
        private int size;

        public DynamicByteArray(int cap) {
          array = new byte[cap > 0 ? cap : 256];
          size = 0;
        }

        public int get(int pos) {
          if (pos >= size) {
            throw new ArrayIndexOutOfBoundsException();
          }
          return array[pos];
        }

        public void add(byte[] bytes) {
          if (size + bytes.length > array.length) {
            byte[] newarray = new byte[array.length + bytes.length * 2];
            System.arraycopy(array, 0, newarray, 0, size);
            array = newarray;
          }
          System.arraycopy(bytes, 0, array, size, bytes.length);
          size += bytes.length;
        }

        public byte[] getResult() {
          return Arrays.copyOfRange(array, 0, size);
        }
    }
    
    public byte[] encodeAvpSet(AvpSet avps) {
        //ByteArrayOutputStream out = new ByteArrayOutputStream();
        DynamicByteArray dba = new DynamicByteArray(0);
        try {
          //DataOutputStream data = new DataOutputStream(out);
          for (Avp a : avps) {
            /*if (a instanceof AvpImpl) {
              AvpImpl aImpl = (AvpImpl) a;
              if (aImpl.rawData.length == 0 && aImpl.groupedData != null) {
                aImpl.rawData = encodeAvpSet(a.getGrouped());
              }
              //data.write(newEncodeAvp(aImpl));
              dba.add(encodeAvp(aImpl));
            }*/
            
            // workaround because of AvpImpl is not public
            boolean hasVendorId = a.getVendorId() != 0;
            int flags = (byte) ((hasVendorId ? 0x80 : 0)
                    | (a.isMandatory() ? 0x40 : 0) | (a.isEncrypted() ? 0x20 : 0));
            AvpImpl aImpl = new AvpImpl(a.getCode(), flags, a.getVendorId(), a.getRawData());
            if (aImpl.rawData.length == 0 && aImpl.groupedData != null) {
              aImpl.rawData = encodeAvpSet(a.getGrouped());
            }
            dba.add(encodeAvp(aImpl));
          }
        }
        catch (Exception e) {
          e.printStackTrace();
          logger.debug("Error during encode avps", e);
        }
        return dba.getResult();
    }
    
    public byte[] int32ToBytes(int value) {
        byte[] bytes = new byte[INT32_SIZE];
        bytes[0] = (byte) (value >> 24 & 0xFF);
        bytes[1] = (byte) (value >> 16 & 0xFF);
        bytes[2] = (byte) (value >> 8 & 0xFF);
        bytes[3] = (byte) (value >> 0 & 0xFF);
        return bytes;
    }
    
    private byte[] concat(int length, byte[]... arrays) {
        if (length == 0) {
            for (byte[] array : arrays) {
                length += array.length;
            }
        }
        byte[] result = new byte[length];
        int pos = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, pos, array.length);
            pos += array.length;
        }
        return result;
    }
    
    private Avp decodeAvp(byte[] in_b ) throws IOException, AvpDataException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(in_b));
        int code = in.readInt();
        int tmp = in.readInt();
        int counter = 0;
        
        int flags = (tmp >> 24) & 0xFF;
        int length = tmp & 0xFFFFFF;
        if (length < 0 || counter + length > in_b.length) {
            throw new AvpDataException("Not enough data in buffer!");
        }
        long vendor = 0;
        boolean hasVendor = false;
        if ((flags & 0x80) != 0) {
            vendor = in.readInt();
            hasVendor = true;
        }
        // Determine body L = length - 4(code) -1(flags) -3(length) [-4(vendor)]
        byte[] rawData = new byte[length - (8 + (hasVendor ? 4 : 0))];
        in.read(rawData);
        // skip remaining.
        // TODO: Do we need to padd everything? Or on send stack should properly fill byte[] ... ?
        if (length % 4 != 0) {
            for (int i; length % 4 != 0; length += i) {
                i = (int) in.skip((4 - length % 4));
            }
        }
        AvpImpl avp = new AvpImpl(code, (short) flags, (int) vendor, rawData);
        return avp;
    }
    
    private AvpSetImpl decodeAvpSet(byte[] buffer, int shift) throws IOException, AvpDataException {
        AvpSetImpl avps = new AvpSetImpl();
        int tmp, counter = shift;
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(buffer, shift, buffer.length /* - shift ? */));

        while (counter < buffer.length) {
          int code = in.readInt();
          tmp = in.readInt();
          int flags = (tmp >> 24) & 0xFF;
          int length  = tmp & 0xFFFFFF;
          if (length < 0 || counter + length > buffer.length) {
            throw new AvpDataException("Not enough data in buffer!");
          }
          long vendor = 0;
          boolean hasVendor = false;
          if ((flags & 0x80) != 0) {
            vendor = in.readInt();
            hasVendor = true;
          }
          // Determine body L = length - 4(code) -1(flags) -3(length) [-4(vendor)]
          byte[] rawData = new byte[length - (8 + (hasVendor ? 4 : 0))];
          in.read(rawData);
          // skip remaining.
          // TODO: Do we need to padd everything? Or on send stack should properly fill byte[] ... ?
          if (length % 4 != 0) {
            for (int i; length % 4 != 0; length += i) {
              i = (int) in.skip((4 - length % 4));
            }
          }
          AvpImpl avp = new AvpImpl(code, (short) flags, (int) vendor, rawData);
          avps.addAvp(avp);
          counter += length;
        }
        return avps;
    }
}
