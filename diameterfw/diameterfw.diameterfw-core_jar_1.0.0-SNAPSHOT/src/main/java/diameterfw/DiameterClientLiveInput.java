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
 * Modified jDiameter ExampleCient.java example
 * 
 * TODO Current client need to have correct Origin and Dest Host and Realm, which reflects the xml config.
 * Should be rewritten to use sctp associations
 */
package diameterfw;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.jdiameter.api.Answer;
import org.jdiameter.api.ApplicationId;
import org.jdiameter.api.Avp;
import org.jdiameter.api.AvpDataException;
import org.jdiameter.api.AvpSet;
import org.jdiameter.api.Configuration;
import org.jdiameter.api.EventListener;
import org.jdiameter.api.IllegalDiameterStateException;
import org.jdiameter.api.InternalException;
import org.jdiameter.api.Message;
import org.jdiameter.api.MetaData;
import org.jdiameter.api.Network;
import org.jdiameter.api.NetworkReqListener;
import org.jdiameter.api.OverloadException;
import org.jdiameter.api.RawSession;
import org.jdiameter.api.Request;
import org.jdiameter.api.RouteException;
import org.jdiameter.api.Session;
import org.jdiameter.api.SessionFactory;
import org.jdiameter.api.Stack;
import org.jdiameter.api.StackType;
import org.jdiameter.client.api.IMessage;
import org.jdiameter.client.impl.parser.MessageParser;
import org.jdiameter.server.impl.StackImpl;
import org.jdiameter.server.impl.helpers.XMLConfiguration;
import org.mobicents.diameter.dictionary.AvpDictionary;
import org.mobicents.diameter.dictionary.AvpRepresentation;
import org.mobicents.protocols.api.Association;
import org.mobicents.protocols.api.AssociationListener;
import org.mobicents.protocols.api.IpChannelType;
import static org.mobicents.protocols.api.IpChannelType.SCTP;
import org.mobicents.protocols.api.ManagementEventListener;
import org.mobicents.protocols.api.PayloadData;
import org.mobicents.protocols.api.Server;
import org.mobicents.protocols.api.ServerListener;
import org.mobicents.protocols.sctp.AssociationImpl;
import org.mobicents.protocols.sctp.ManagementImpl;

public class DiameterClientLiveInput implements ManagementEventListener, ServerListener, AssociationListener, EventListener<Request, Answer> {

        // SCTP
        final public static boolean USE_RAW_SCTP_IMPL = false;   // set this true, to use SCTP impl (configured inline) instead of jDiameter client (configuration in resource/client-jdiameter-config.xml). The sctp impl does not rewrite the Dest Host and Realm and keep original traffic, but does not currently send CER, DWR, DPR.
        public static ManagementImpl sctpManagement;
        final public static String sctp_assoc_name = "client_to_firewall";
        
        static final private String persistDir = "XmlDiameterClientLiveInput";
    
	private static final Logger logger = Logger.getLogger(DiameterClientLiveInput.class);
	static {
            //configure logging.
            configLog4j();
	}
	
	private static void configLog4j() {
            InputStream inStreamLog4j = DiameterClientLiveInput.class.getClassLoader().getResourceAsStream("log4j.properties");
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
            logger.debug("log4j configured");
	}
	
	//configuration files
	private static final String configFile = "client-jdiameter-config.xml";
	private static final String dictionaryFile = "dictionary.xml";
	//our destination
	private static final String serverHost = "127.0.0.1";
	private static final String serverPort = "3868";
	private static final String serverURI = "aaa://" + serverHost + ":" + serverPort;
	//our realm
	private static final String realmName = "exchangeClient.example.org";
	// definition of codes, IDs
	private static final int commandCode = 316;
	private static final long vendorID = 66666;
	private static final long applicationID = 16777251;
	private ApplicationId authAppId = ApplicationId.createByAuthAppId(applicationID);
	private static final int exchangeTypeCode = 888;
	private static final int exchangeDataCode = 999;
	// enum values for Exchange-Type AVP
	private static final int EXCHANGE_TYPE_INITIAL = 0;
	private static final int EXCHANGE_TYPE_INTERMEDIATE = 1;
	private static final int EXCHANGE_TYPE_TERMINATING = 2;
	//list of data we want to exchange.
	private static final String[] TO_SEND = new String[] { "I want to get 3 answers", "This is second message", "Bye bye" };
	//Dictionary, for informational purposes.
	private AvpDictionary dictionary = AvpDictionary.INSTANCE;
	//stack and session factory
	private Stack stack;
	private SessionFactory factory;

	// ////////////////////////////////////////
	// Objects which will be used in action //
	// ////////////////////////////////////////
	public Session session;  // session used as handle for communication
	private int toSendIndex = 0;  //index in TO_SEND table
	private boolean finished = false;  //boolean telling if we finished our interaction
        
        // Diameter
        public final MessageParser parser = new MessageParser();
        
        private void initSCTP(IpChannelType ipChannelType) throws Exception {
            logger.debug("Initializing SCTP Stack ....");
            this.sctpManagement = new ManagementImpl("DiameterClientLiveInput");
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


            // Create SCTP Client Association
            AssociationImpl clientAssociation = this.sctpManagement.addAssociation(
                    "127.0.0.1",
                    13868,
                    "127.0.0.1",
                    3869,
                    sctp_assoc_name,
                    ipChannelType,
                    null
            );
            clientAssociation.setAssociationListener(this);
            this.sctpManagement.startAssociation(sctp_assoc_name);
            
            
            logger.debug("Initialized SCTP Stack ....");
        }

	private void initStack() {
            if (logger.isInfoEnabled()) {
                logger.info("Initializing Stack...");
            }
            InputStream is = null;
            try {
                //Parse dictionary, it is used for user friendly info.
                dictionary.parseDictionary(this.getClass().getClassLoader().getResourceAsStream(dictionaryFile));
                logger.info("AVP Dictionary successfully parsed.");

                this.stack = new StackImpl();
                //Parse stack configuration
                is = this.getClass().getClassLoader().getResourceAsStream(configFile);
                Configuration config = new XMLConfiguration(is);
                factory = stack.init(config);
                if (logger.isInfoEnabled()) {
                        logger.info("Stack Configuration successfully loaded.");
                }
                //Print info about applicatio
                Set<org.jdiameter.api.ApplicationId> appIds = stack.getMetaData().getLocalPeer().getCommonApplications();

                logger.info("Diameter Stack  :: Supporting " + appIds.size() + " applications.");
                for (org.jdiameter.api.ApplicationId x : appIds) {
                        logger.info("Diameter Stack  :: Common :: " + x);
                }
                is.close();
                //Register network req listener, even though we wont receive requests
                //this has to be done to inform stack that we support application
                Network network = stack.unwrap(Network.class);
                network.addNetworkReqListener(new NetworkReqListener() {

                        @Override
                        public Answer processRequest(Request request) {
                                //this wontbe called.
                                return null;
                        }
                }, this.authAppId); //passing our example app id.
                

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

            MetaData metaData = stack.getMetaData();
            //ignore for now.
            if (metaData.getStackType() != StackType.TYPE_SERVER || metaData.getMinorVersion() <= 0) {
                stack.destroy();
                if (logger.isEnabledFor(org.apache.log4j.Level.ERROR)) {
                        logger.error("Incorrect driver");
                }
                return;
            }

            try {
                if (logger.isInfoEnabled()) {
                    logger.info("Starting stack");
                }
                stack.start();
                if (logger.isInfoEnabled()) {
                    logger.info("Stack is running.");
                }
            } catch (Exception e) {
                e.printStackTrace();
                stack.destroy();
                return;
            }
            if (logger.isInfoEnabled()) {
                logger.info("Stack initialization successfully completed.");
            }
	}

	/**
	 * @return
	 */
	private boolean finished() {
            return this.finished;
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
        
	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jdiameter.api.EventListener#receivedSuccessMessage(org.jdiameter
	 * .api.Message, org.jdiameter.api.Message)
	 */
	@Override
	public void receivedSuccessMessage(Request request, Answer answer) {

        }

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.jdiameter.api.EventListener#timeoutExpired(org.jdiameter.api.
	 * Message)
	 */
	@Override
	public void timeoutExpired(Request request) {	

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

	public static void main(String[] args) {
            
            if (USE_RAW_SCTP_IMPL) {
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
            }
            
            DiameterClientLiveInput ec = new DiameterClientLiveInput();
            
            if (USE_RAW_SCTP_IMPL) {
                try {
                    ec.initSCTP(IpChannelType.SCTP);
                } catch (Exception ex) {
                    java.util.logging.Logger.getLogger(DiameterClientLiveInput.class.getName()).log(Level.SEVERE, null, ex);
                }
            } else {
                ec.initStack();
            }

            while (!ec.finished()) {
                try {
                    // Connect to the named pipe
                    RandomAccessFile br = new RandomAccessFile("input/pipe", "r");

                    String strLine;

                    //Read File Line By Line
                    while (true) {
                        while ((strLine = br.readLine()) != null) {
                            // Print the content on the console
                            //logger.debug(strLine);

                            String str = strLine;
                            int i = str.indexOf("diameter_raw");
                            while (i != -1) {
                                //logger.debug(strLine);
                                i += "diameter_raw\": ".length();
                                str = str.substring(i);
                                //logger.debug(s);
                                String s = str.split("\"")[1];
                                //logger.debug(s);

                                ByteBuffer buf = ByteBuffer.wrap(hexStringToByteArray(s));
                                Message msg = ec.parser.createMessage(buf);
                                
                                if (msg != null && msg.isRequest()) {
                                    
                                    ec.dumpMessage(msg, true);
                                    
                                    if (USE_RAW_SCTP_IMPL) {
                                        ByteBuffer byteBuffer = ec.parser.encodeMessage((IMessage)msg);
                                        PayloadData payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, 0, 0);

                                        ec.sctpManagement.getAssociation(ec.sctp_assoc_name).send(payloadData);
                                    } else {
                                        ec.session = ec.factory.getNewSession("CretedByDiameterLiveClient;" + System.currentTimeMillis());
                                        Request r = ec.session.createRequest(msg.getCommandCode(), ApplicationId.createByAuthAppId(msg.getApplicationId()), ec.realmName, ec.serverURI);
                                        
                                        AvpSet avpSet = msg.getAvps();
                                        AvpSet avpSetR = r.getAvps();


                                        //Avp avp;
                                        for (int j = 0; j < avpSetR.size(); j++) {
                                            avpSetR.removeAvpByIndex(j);
                                        }
                                        for (int j = 0; j < avpSet.size(); j++) {
                                            avpSetR.addAvp(avpSet.getAvpByIndex(j));
                                        }
                                        avpSetR.removeAvp(Avp.DESTINATION_REALM);
                                        //byte[] b = hexStringToByteArray("65786368616e67652e6578616d706c652e6f7267");
                                        avpSetR.addAvp(Avp.DESTINATION_REALM, "exchange.example.org", true, false, true);

                                        avpSetR.removeAvp(Avp.ORIGIN_REALM);
                                        
                                        ec.session.send(r);
                                    }
                                    
                                }
                                    
                                i = str.indexOf("diameter_raw");
                            }

                            // TODO, remove if not needed
                            // added only for visibility, to not have many sctp streams in wireshark
                            //Thread.sleep(100);
                        }
                        //logger.debug("Waiting ...");
                        Thread.sleep(1000);
                    }
                    //Close the input stream
                    //br.close();
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } catch (FileNotFoundException ex) {
                    java.util.logging.Logger.getLogger(DiameterClientLiveInput.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    java.util.logging.Logger.getLogger(DiameterClientLiveInput.class.getName()).log(Level.SEVERE, null, ex);
                } catch (AvpDataException ex) {
                    java.util.logging.Logger.getLogger(DiameterClientLiveInput.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InternalException ex) {
                    java.util.logging.Logger.getLogger(DiameterClientLiveInput.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IllegalDiameterStateException ex) {
                    java.util.logging.Logger.getLogger(DiameterClientLiveInput.class.getName()).log(Level.SEVERE, null, ex);
                } catch (RouteException ex) {
                    java.util.logging.Logger.getLogger(DiameterClientLiveInput.class.getName()).log(Level.SEVERE, null, ex);
                } catch (OverloadException ex) {
                    java.util.logging.Logger.getLogger(DiameterClientLiveInput.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    java.util.logging.Logger.getLogger(DiameterClientLiveInput.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
	}

    public void onServiceStarted() {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onServiceStopped() {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onRemoveAllResources() {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onServerAdded(Server server) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onServerRemoved(Server server) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onAssociationAdded(Association asctn) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onAssociationRemoved(Association asctn) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onAssociationStarted(Association asctn) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onAssociationStopped(Association asctn) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onAssociationUp(Association asctn) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onAssociationDown(Association asctn) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onNewRemoteConnection(Server server, Association asctn) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onCommunicationUp(Association asctn, int i, int i1) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onCommunicationShutdown(Association asctn) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onCommunicationLost(Association asctn) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onCommunicationRestart(Association asctn) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void onPayload(Association asctn, PayloadData pd) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void inValidStreamId(PayloadData pd) {
        logger.debug("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}