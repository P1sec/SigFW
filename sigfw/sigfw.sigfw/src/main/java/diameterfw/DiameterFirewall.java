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
import org.mobicents.protocols.sctp.netty.NettyAssociationImpl;
import org.mobicents.protocols.sctp.netty.NettySctpManagementImpl;
import sigfw.common.Crypto;

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
    public final MessageParser parser = new MessageParser();
    
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
    
    static Random randomGenerator = new Random();

    static final private String persistDir = "XmlDiameterFirewall";
    
    static final private int CC_AUTO_ENCRYPTION = 999;
    static final private int AVP_AUTO_ENCRYPTION_CAPABILITIES = 1101;
    static final private int AVP_AUTO_ENCRYPTION_REALM = 1102;
    static final private int AVP_AUTO_ENCRYPTION_PUBLIC_KEY = 1103;
    static final private int AVP_AUTO_ENCRYPTION_PUBLIC_KEY_TYPE = 1104;

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
        
        this.sctpManagement.setSingleThread(false);

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
                String session_id = ai + ":" + cc + ":" + orig_realm + ":" + msg.getEndToEndIdentifier() + ":" + msg.getHopByHopIdentifier();
                if (diameter_sessions.containsKey(session_id)) {
                    _dest_realm = diameter_sessions.get(session_id);
                }
                if (DiameterFirewallConfig.destination_realm_decryption.containsKey(_dest_realm)) {
                    KeyPair keyPair = DiameterFirewallConfig.destination_realm_decryption.get(_dest_realm);
                    logger.debug("Diameter Decryption of Answer for Destination Realm = " + _dest_realm);

                    // decrypt
                    String r = crypto.diameterDecrypt(msg, keyPair);
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
                        
                        // Capabilities
                        // TODO
                        answer.getAvps().addAvp(AVP_AUTO_ENCRYPTION_CAPABILITIES, "Av1".getBytes());

                        // Realm
                        answer.getAvps().addAvp(AVP_AUTO_ENCRYPTION_REALM, dest_realm.getBytes());

                        // Public key type
                        String publicKeyType = "";
                        if (myKeyPair.getPublic() instanceof RSAPublicKey) {
                            publicKeyType = "RSA";
                        } else if (myKeyPair.getPublic() instanceof ECPublicKey) {
                            publicKeyType = "EC";
                        }
                        answer.getAvps().addAvp(AVP_AUTO_ENCRYPTION_PUBLIC_KEY_TYPE, publicKeyType.getBytes());
                        
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
                    
                    // Capabilities
                    // TODO
                    
                    // Realm prefix
                    String realm = "";
                    if (msg.getAvps().getAvp(AVP_AUTO_ENCRYPTION_REALM) != null) {
                        byte[] d2 = msg.getAvps().getAvp(AVP_AUTO_ENCRYPTION_REALM).getOctetString();
                        realm = new String(d2);
                    }
                    
                    // Public key type
                    String publicKeyType = "RSA";
                    if (msg.getAvps().getAvp(AVP_AUTO_ENCRYPTION_PUBLIC_KEY_TYPE) != null) {
                        byte[] d3 = msg.getAvps().getAvp(AVP_AUTO_ENCRYPTION_PUBLIC_KEY_TYPE).getOctetString();
                        
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
            
            // --------------- Diameter signature ---------------
            // Sign only Requests containing Orig-Realm
            if (!orig_realm.equals("") && msg.isRequest()) {
                // ------------- Diameter verify --------------
                if (DiameterFirewallConfig.origin_realm_verify.containsKey(orig_realm)) {
                    PublicKey publicKey = DiameterFirewallConfig.origin_realm_verify.get(orig_realm);
                    String r = crypto.diameterVerify(msg, publicKey);
                    if (!r.equals("")) {
                        firewallMessage(asctn, pd.getPayloadProtocolId(), pd.getStreamNumber(), msg, r, lua_hmap);
                        return;
                    }
                } 
                // No key to verify signature
                else {
                    // TODO could initiate key autodiscovery
                }
                // --------------------------------------------
                // ------------- Diameter signing -------------
                if (DiameterFirewallConfig.origin_realm_signing.containsKey(orig_realm)) {
                    KeyPair keyPair = DiameterFirewallConfig.origin_realm_signing.get(orig_realm);
                    crypto.diameterSign(msg, keyPair);
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
                // diameterEncrypt(msg, publicKey);
                // changed to v2 to use encrypted grouped AVP
                crypto.diameterEncrypt_v2(msg, publicKey);
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
                // diameterEncrypt(msg, publicKey);
                // changed to v2 to use encrypted grouped AVP
                crypto.diameterEncrypt_v2(msg, publicKey);

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
                        crypto.diameterSign(message, keyPair);
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

    @Override
    public void onServerModified(Server server) {
        logger.debug("[[[[[[[[[[    onServerModified      ]]]]]]]]]]");
    }

    @Override
    public void onAssociationModified(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationModified      ]]]]]]]]]]");
    }
}
