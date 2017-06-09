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
 * Modified jDiameter ExampleServer.java example
 * 
 * TODO Current server need to have correct Origin and Dest Host and Realm, which reflects the xml config.
 * Should be rewritten to use sctp associations
 */
package diameterfw;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.Set;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.jdiameter.api.Answer;
import org.jdiameter.api.ApplicationId;
import org.jdiameter.api.Avp;
import org.jdiameter.api.AvpDataException;
import org.jdiameter.api.AvpSet;
import org.jdiameter.api.Configuration;
import org.jdiameter.api.InternalException;
import org.jdiameter.api.Message;
import org.jdiameter.api.MetaData;
import org.jdiameter.api.Network;
import org.jdiameter.api.NetworkReqListener;
import org.jdiameter.api.Request;
import org.jdiameter.api.Session;
import org.jdiameter.api.SessionFactory;
import org.jdiameter.api.Stack;
import org.jdiameter.api.StackType;
import org.jdiameter.server.impl.StackImpl;
import org.jdiameter.server.impl.helpers.XMLConfiguration;
import org.mobicents.diameter.dictionary.AvpDictionary;
import org.mobicents.diameter.dictionary.AvpRepresentation;

/**
 * @author baranowb
 * 
 */
public class DiameterServer implements NetworkReqListener {
	private static final Logger log = Logger.getLogger(DiameterServer.class);
	static{

		configLog4j();
	
}

private static void configLog4j() {
	InputStream inStreamLog4j = DiameterServer.class.getClassLoader().getResourceAsStream("log4j.properties");
	Properties propertiesLog4j = new Properties();
	try {
		propertiesLog4j.load(inStreamLog4j);
		PropertyConfigurator.configure(propertiesLog4j);
	} catch (Exception e) {
		e.printStackTrace();
	}

	log.debug("log4j configured");

}
	private static final String configFile = "server-jdiameter-config.xml";
	private static final String dictionaryFile = "dictionary.xml";
	private static final String realmName = "exchange.example.org";
	// Defs for our app
	private static final int commandCode = 316;
	private static final long vendorID = 66666;
	private static final long applicationID = 16777251;
	private ApplicationId authAppId = ApplicationId.createByAuthAppId(applicationID);;
	private static final int exchangeTypeCode = 888;
	private static final int exchangeDataCode = 999;
	// enum values for Exchange-Type AVP
	private static final int EXCHANGE_TYPE_INITIAL = 0;
	private static final int EXCHANGE_TYPE_INTERMEDIATE = 1;
	private static final int EXCHANGE_TYPE_TERMINATING = 2;
	
	private static final String[] TO_RECEIVE = new String[] { "I want to get 3 answers", "This is second message", "Bye bye" };
	private AvpDictionary dictionary = AvpDictionary.INSTANCE;
	private Stack stack;
	private SessionFactory factory;

	// ////////////////////////////////////////
	// Objects which will be used in action //
	// ////////////////////////////////////////
	private Session session;
	private int toReceiveIndex = 0;
	private boolean finished = false;

	private void initStack() {

            if (log.isInfoEnabled()) {
                    log.info("Initializing Stack...");
            }
            InputStream is = null;
            try {
                dictionary.parseDictionary(this.getClass().getClassLoader().getResourceAsStream(dictionaryFile));
                log.info("AVP Dictionary successfully parsed.");
                this.stack = new StackImpl();

                is = this.getClass().getClassLoader().getResourceAsStream(configFile);

                Configuration config = new XMLConfiguration(is);
                factory = stack.init(config);
                if (log.isInfoEnabled()) {
                    log.info("Stack Configuration successfully loaded.");
                }

                Set<org.jdiameter.api.ApplicationId> appIds = stack.getMetaData().getLocalPeer().getCommonApplications();

                log.info("Diameter Stack  :: Supporting " + appIds.size() + " applications.");
                for (org.jdiameter.api.ApplicationId x : appIds) {
                    log.info("Diameter Stack  :: Common :: " + x);
                }
                is.close();
                Network network = stack.unwrap(Network.class);
                network.addNetworkReqListener(this, this.authAppId);
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
            if (metaData.getStackType() != StackType.TYPE_SERVER || metaData.getMinorVersion() <= 0) {
                stack.destroy();
                if (log.isEnabledFor(org.apache.log4j.Level.ERROR)) {
                        log.error("Incorrect driver");
                }
                return;
            }

            try {
                if (log.isInfoEnabled()) {
                        log.info("Starting stack");
                }
                stack.start();
                if (log.isInfoEnabled()) {
                        log.info("Stack is running.");
                }
            } catch (Exception e) {
                e.printStackTrace();
                stack.destroy();
                return;
            }
            if (log.isInfoEnabled()) {
                log.info("Stack initialization successfully completed.");
            }
	}
	
	private void dumpMessage(Message message, boolean sending) {
            if (log.isInfoEnabled()) {
                    log.info((sending?"Sending ":"Received ") + (message.isRequest() ? "Request: " : "Answer: ") + message.getCommandCode() + "\nE2E:"
                                    + message.getEndToEndIdentifier() + "\nHBH:" + message.getHopByHopIdentifier() + "\nAppID:" + message.getApplicationId());
                    log.info("AVPS["+message.getAvps().size()+"]: \n");
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
                    log.info(prefix + "<avp name=\"" + avpRep.getName() + "\" code=\"" + avp.getCode() + "\" vendor=\"" + avp.getVendorId() + "\">");
                    printAvpsAux(avp.getGrouped(), level + 1);
                    log.info(prefix + "</avp>");
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

                    log.info(prefix + "<avp name=\"" + avpRep.getName() + "\" code=\"" + avp.getCode() + "\" vendor=\"" + avp.getVendorId()
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
            DiameterServer es = new DiameterServer();
            es.initStack();

            while (!es.finished()) {
                try {
                        Thread.currentThread().sleep(5000);
                } catch (InterruptedException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                }
            }
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.jdiameter.api.NetworkReqListener#processRequest(org.jdiameter.api
	 * .Request)
	 */
	@Override
	public Answer processRequest(Request request) {
            dumpMessage(request,false);
            if (request.getCommandCode() != commandCode) {
                log.error("Received bad answer: " + request.getCommandCode());
                return null;
            }
            AvpSet requestAvpSet = request.getAvps();

            Avp exchangeTypeAvp = requestAvpSet.getAvp(exchangeTypeCode, vendorID);
            Avp exchangeDataAvp = requestAvpSet.getAvp(exchangeDataCode, vendorID);
            if (exchangeTypeAvp == null) {
                log.error("Request does not have Exchange-Type");

                Answer answer = createAnswer(request, 5004, EXCHANGE_TYPE_TERMINATING); 
                dumpMessage(answer,true);
                return answer; // set
                                                                                                                                                    // exchange
                                                                                                                                                    // type
                                                                                                                                                    // to
                                                                                                                                                    // terminating
            }
            if (exchangeDataAvp == null) {
                log.error("Request does not have Exchange-Data");
                Answer answer = createAnswer(request, 5004, EXCHANGE_TYPE_TERMINATING); 
                dumpMessage(answer,true);
                return answer; // set
                                                                                                                                                    // exchange
                                                                                                                                                    // type
                                                                                                                                                    // to
                                                                                                                                                    // terminating
            }
            // cast back to int(Enumerated is Unsigned32, and API represents it as
            // long so its easier
            // to manipulate
            try {
                switch ((int) exchangeTypeAvp.getUnsigned32()) {
                case EXCHANGE_TYPE_INITIAL:
                    // JIC check;
                    String data = exchangeDataAvp.getUTF8String();
                    this.session = this.factory.getNewSession(request.getSessionId());
                    if (data.equals(TO_RECEIVE[toReceiveIndex])) {
                        // create session;

                        Answer answer = createAnswer(request, 2001, EXCHANGE_TYPE_INITIAL); // set
                                                                                                                                                                                // exchange
                                                                                                                                                                                // type
                                                                                                                                                                                // to
                                                                                                                                                                                // terminating
                        toReceiveIndex++;
                        dumpMessage(answer,true);
                        return answer;
                    } else {
                        log.error("Received wrong Exchange-Data: " + data);
                        Answer answer = request.createAnswer(6000);
                    }
                    break;
                case EXCHANGE_TYPE_INTERMEDIATE:
                    // JIC check;
                    data = exchangeDataAvp.getUTF8String();
                    if (data.equals(TO_RECEIVE[toReceiveIndex])) {

                        Answer answer = createAnswer(request, 2001, EXCHANGE_TYPE_INTERMEDIATE); // set
                                                                                                                                                                                // exchange
                                                                                                                                                                                // type
                                                                                                                                                                                // to
                                                                                                                                                                                // terminating
                        toReceiveIndex++;
                        dumpMessage(answer,true);
                        return answer;
                    } else {
                        log.error("Received wrong Exchange-Data: " + data);
                    }
                    break;
                case EXCHANGE_TYPE_TERMINATING:
                    data = exchangeDataAvp.getUTF8String();
                    if (data.equals(TO_RECEIVE[toReceiveIndex])) {
                        // good, we reached end of FSM.
                        finished = true;
                        // release session and its resources.
                        Answer answer = createAnswer(request, 2001, EXCHANGE_TYPE_TERMINATING); // set
                                                                                                                                                                        // exchange
                                                                                                                                                                        // type
                                                                                                                                                                        // to
                                                                                                                                                                        // terminating
                        toReceiveIndex++;
                        this.session.release();
                        finished = true;
                        this.session = null;
                        dumpMessage(answer,true);
                        return answer;

                    } else {
                        log.error("Received wrong Exchange-Data: " + data);
                    }
                    break;
                default:
                    log.error("Bad value of Exchange-Type avp: " + exchangeTypeAvp.getUnsigned32());
                    break;
                }
            } catch (AvpDataException e) {
                // thrown when interpretation of byte[] fails
                e.printStackTrace();
            } catch (InternalException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            //error, something bad happened.
            finished = true;
            return null;
	}

	private Answer createAnswer(Request r, int resultCode, int enumType) {
            Answer answer = r.createAnswer(resultCode);
            AvpSet answerAvps = answer.getAvps();
            // code , value , vendor, mandatory,protected,isUnsigned32
            // (Enumerated)
            Avp exchangeType = answerAvps.addAvp(exchangeTypeCode, (long) enumType, vendorID, true, false, true); // value
                                                                                                                                                                                                                            // is
                                                                                                                                                                                                                            // set
                                                                                                                                                                                                                            // on
                                                                                                                                                                                                                            // creation
            // code , value , vendor, mandatory,protected, isOctetString
            Avp exchengeData = answerAvps.addAvp(exchangeDataCode, TO_RECEIVE[toReceiveIndex], vendorID, true, false, false); // value
                                                                                                                                                                                                                                                    // is
                                                                                                                                                                                                                                                    // set
                                                                                                                                                                                                                                                    // on
                                                                                                                                                                                                                                                    // creation


            //add origin, its required by duplicate detection
            //answerAvps.addAvp(Avp.ORIGIN_HOST, stack.getMetaData().getLocalPeer().getUri().getFQDN(), true, false, true);
            //answerAvps.addAvp(Avp.ORIGIN_REALM, stack.getMetaData().getLocalPeer().getRealmName(), true, false, true);
            answerAvps.addAvp(Avp.ORIGIN_HOST, r.getAvps().getAvp(Avp.ORIGIN_HOST).getRawData());
            answerAvps.addAvp(Avp.ORIGIN_REALM, r.getAvps().getAvp(Avp.ORIGIN_REALM).getRawData());
            return answer;
	}
}
