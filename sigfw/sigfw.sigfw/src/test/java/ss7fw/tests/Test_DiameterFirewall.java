/*
 * JUNIT DiameterFirewall class
 *
 * SigFW
 * Open Source SS7/Diameter firewall
 *
 * Copyright 2017, H21 lab, P1 Security and by all individual authors and contributors
 * See the AUTHORS in the for a full listing of authors and contributors.
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
 */
package ss7fw.tests;

import diameterfw.DiameterClientLiveInput;
import java.util.logging.Level;
import org.junit.Assert;
import org.junit.Test;
import org.mobicents.protocols.api.IpChannelType;
import diameterfw.DiameterFirewall;
import diameterfw.DiameterFirewallConfig;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Properties;
import java.util.logging.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.jdiameter.api.AvpDataException;
import org.jdiameter.api.Message;
import org.jdiameter.client.api.IMessage;
import org.jdiameter.client.api.parser.ParseException;
import org.junit.BeforeClass;
import org.mobicents.protocols.api.PayloadData;

public class Test_DiameterFirewall {
    
    private static DiameterFirewall sigfw = null;
    
    private static org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(Test_DiameterFirewall.class);

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

    private static void initializeDiameterFirewall() {
        configLog4j();
        
        try {
            // Use last config
            DiameterFirewallConfig.loadConfigFromFile("diameterfw_junit.json");
            // TODO use the following directive instead to do not use .last configs
            //SS7FirewallConfig.loadConfigFromFile(configName);
        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }

        sigfw = new DiameterFirewall();
        sigfw.unitTesting = true;

        try {
            sigfw.initStack(IpChannelType.SCTP);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }
    
    @BeforeClass
    public static void testDiameterFirewallInit() {
        initializeDiameterFirewall();
    }
    
    @Test
    public void testULR() {

        logger.info("[[[[[[[[[[   ULR      ]]]]]]]]]]");
        
        // ULR
        sigfw.resetUnitTestingFlags();
        
        ByteBuffer buf = ByteBuffer.wrap(DiameterClientLiveInput.hexStringToByteArray("010000f88000013c010000230bbb735b3b4000020000010740000037426164437573746f6d53657373696f6e49643b596573576543616e5061737349643b3135303737333033363031323400000001024000000c010000230000011b4000001c65786368616e67652e6578616d706c652e6f726700000108400000113132372e302e302e31000000000001284000002265786368616e6765436c69656e742e6578616d706c652e6f7267000000000001400000183131313131313131313131313131313100000378c00000100001046a00000000000003e7c00000230001046a492077616e7420746f20676574203320616e737765727300"));
        Message msg;
        try {
            msg = sigfw.parser.createMessage(buf);
            ByteBuffer byteBuffer;
            byteBuffer = sigfw.parser.encodeMessage((IMessage)msg);
            PayloadData payloadData = new PayloadData(byteBuffer.array().length, byteBuffer.array(), true, false, 0, 0);
            sigfw.onPayload(null, payloadData);
        } catch (AvpDataException ex) {
            Logger.getLogger(Test_DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ParseException ex) {
            Logger.getLogger(Test_DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(Test_DiameterFirewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        Assert.assertTrue("This ULR message (CommandCode 316, Request) should be allowed by LUA rules diameter_orig_realm", !sigfw.unitTestingFlags_sendDiameterMessage);

        
    }
    

}
