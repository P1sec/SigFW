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
 * Modified jSS7 SctpClient.java example
 */
package sigfw.common;

import java.io.InputStream;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.mobicents.protocols.api.Association;
import org.mobicents.protocols.api.PayloadData;
import org.mobicents.protocols.ss7.sccp.message.SccpDataMessage;
import com.p1sec.sigfw.SigFW_interface.FirewallRulesInterface;

/**
 *
 * @author Martin Kacer
 */
public class ExternalFirewallRules implements FirewallRulesInterface {
    protected static final Logger logger = Logger.getLogger(ExternalFirewallRules.class);
    static {
        configLog4j();
    }
    
    protected static void configLog4j() {
        InputStream inStreamLog4j = ExternalFirewallRules.class.getClassLoader().getResourceAsStream("log4j.properties");
        Properties propertiesLog4j = new Properties();
        try {
            propertiesLog4j.load(inStreamLog4j);
            PropertyConfigurator.configure(propertiesLog4j);
        } catch (Exception e) {
            e.printStackTrace();
        }

        logger.debug("log4j configured");

    }
    
    public boolean ss7FirewallRules(SccpDataMessage message) {
        logger.debug("ExternalFirewallRules::ss7FirewallRules");
        
        return true;
    }
    
    public boolean diameterFirewallRules(Association asctn, PayloadData pd) {
        logger.debug("ExternalFirewallRules::diameterFirewallRules");
        
        return true;
    }
    
}
