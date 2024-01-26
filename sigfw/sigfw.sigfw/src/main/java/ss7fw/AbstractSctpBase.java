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
 * Modified jSS7 AbstractSctpBase.java example
 */
package ss7fw;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.FileAppender;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.SimpleLayout;
import org.mobicents.protocols.ss7.map.api.MAPDialogListener;
import org.mobicents.protocols.ss7.m3ua.impl.parameter.ParameterFactoryImpl;

/**
 * Reused from jSS7 SctpClient and SctpServer example
 * @author Martin Kacer
 * original author amit bhayani in jSS7 SctpClient.java example
 */
public abstract class AbstractSctpBase/*, MAPServiceSupplementaryListener*/ {

    private static final Logger logger = Logger.getLogger("map.test");

    protected static final String LOG_FILE_NAME = "log.file.name";
    protected static String logFileName = "maplog.txt";

    // MTP Details
    protected int minOpc = 0;
    protected int maxOpc = 100000;
    
    protected final int CLIENT_SPC = 1;
    protected final int SERVER_SPC = 2;
    protected final int NETWORK_INDICATOR = 0;
    protected final int SERVICE_INIDCATOR = 3; // SCCP
    protected final int SSN = 8;

    // M3UA details
    // protected final String CLIENT_IP = "172.31.96.40";
    protected final String CLIENT_IP = "127.0.0.1";
    protected final int CLIENT_PORT = 2345;

    // protected final String SERVER_IP = "172.31.96.41";
    protected final String SERVER_IP = "127.0.0.1";
    protected final int SERVER_PORT = 3434;

    protected final int ROUTING_CONTEXT = 100;

    protected final String SERVER_ASSOCIATION_NAME = "serverAssociation";
    protected final String CLIENT_ASSOCIATION_NAME = "clientAssociation";

    protected final String SERVER_NAME = "testserver";

    //protected final SccpAddress SCCP_CLIENT_ADDRESS = new SccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN,
    //          CLIENT_SPC, null, SSN);
    //protected final SccpAddress SCCP_SERVER_ADDRESS = new SccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN,
    //          SERVET_SPC, null, SSN);
    protected final ParameterFactoryImpl factory = new ParameterFactoryImpl();

    protected AbstractSctpBase() {
        init();
    }

    public void init() {
        try {
            Properties tckProperties = new Properties();

            InputStream inStreamLog4j = AbstractSctpBase.class.getResourceAsStream("/log4j.properties");

            System.out.println("Input Stream = " + inStreamLog4j);

            Properties propertiesLog4j = new Properties();
            try {
                propertiesLog4j.load(inStreamLog4j);
                PropertyConfigurator.configure(propertiesLog4j);
            } catch (IOException e) {
                e.printStackTrace();
                BasicConfigurator.configure();
            }

            logger.debug("log4j configured");

            String lf = System.getProperties().getProperty(LOG_FILE_NAME);
            if (lf != null) {
                logFileName = lf;
            }

            // If already created a print writer then just use it.
            try {
                logger.addAppender(new FileAppender(new SimpleLayout(), logFileName));
            } catch (FileNotFoundException fnfe) {

            }
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException(ex);
        }

    }
}
