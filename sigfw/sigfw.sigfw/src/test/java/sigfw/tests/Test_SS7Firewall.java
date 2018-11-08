/**
 * JUNIT SS7Firewall class
 * 
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
 */
package sigfw.tests;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.ss7.indicator.NatureOfAddress;
import org.mobicents.protocols.ss7.indicator.RoutingIndicator;
import org.mobicents.protocols.ss7.sccp.message.SccpDataMessage;
import org.mobicents.protocols.ss7.sccp.parameter.GlobalTitle;
import org.mobicents.protocols.ss7.sccp.parameter.SccpAddress;
import static ss7fw.SS7Client.hexStringToByteArray;
import ss7fw.SS7Firewall;
import ss7fw.SS7FirewallConfig;

public class Test_SS7Firewall {
    
    private static SS7Firewall sigfw = null;
    private static SccpAddress callingParty;
    private static SccpAddress calledParty;

    private static void initializeSS7Firewall() {
        try {
            // Use last config
            SS7FirewallConfig.loadConfigFromFile("ss7fw_junit.json");
            // TODO use the following directive instead to do not use .last configs
            //SS7FirewallConfig.loadConfigFromFile(configName);
        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(SS7FirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }

        sigfw = new SS7Firewall();
        sigfw.unitTesting = true;

        try {
            sigfw.initializeStack(IpChannelType.SCTP);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // set the calling and called GT for unittests
        GlobalTitle callingGT = sigfw.sccpStack.getSccpProvider().getParameterFactory().createGlobalTitle("111111111111", 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_MOBILE, null, NatureOfAddress.INTERNATIONAL);
        GlobalTitle calledGT = sigfw.sccpStack.getSccpProvider().getParameterFactory().createGlobalTitle("000000000000", 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_MOBILE, null, NatureOfAddress.INTERNATIONAL);
        callingParty = sigfw.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, callingGT, 1, 8);
        calledParty = sigfw.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, calledGT, 2, 8);
    }
    
    @BeforeClass
    public static void testSS7FirewallInit() {
        initializeSS7Firewall();
    }
    
    @Test
    public void testATI() {
        // anyTimeInterrogation
        sigfw.resetUnitTestingFlags();
        SccpDataMessage sccpDataMessage = sigfw.sccpStack.getSccpProvider().getMessageFactory().createDataMessageClass0(calledParty, callingParty, hexStringToByteArray("627e4804000000026b432841060700118605010101a036603480020780a109060704000001001d03be232821060704000001010101a016a01480099611111111111111f18107961111111111f16c31a12f0201000201473027a009800711111111111111a10f80008100830084010086008500870083099611111111111111f1"), 0, true, null, null);
        sigfw.onMessage(sccpDataMessage);
        
        try {
            Thread.currentThread().sleep(100);
        } catch (InterruptedException ex) {
            Logger.getLogger(Test_SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        Assert.assertTrue("anyTimeInterrogation message (opCode 71, TCAP Begin) should be blocked by Cat1", !sigfw.unitTestingFlags_sendSccpMessage);
    }
    
    @Test
    public void testPSL() {
        // provideSubscriberLocation
        sigfw.resetUnitTestingFlags();
        SccpDataMessage sccpDataMessage = sigfw.sccpStack.getSccpProvider().getMessageFactory().createDataMessageClass0(calledParty, callingParty, hexStringToByteArray("62454804000000536b1a2818060700118605010101a00d600ba1090607040000010026036c21a11f020101020153301730038001010407911111111111118307111111111111f1"), 0, true, null, null);
        sigfw.onMessage(sccpDataMessage);
        
        try {
            Thread.currentThread().sleep(100);
        } catch (InterruptedException ex) {
            Logger.getLogger(Test_SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        Assert.assertTrue("provideSubscriberLocation message (opCode 83, TCAP Begin) should be blocked by Cat1", !sigfw.unitTestingFlags_sendSccpMessage);
    }
    
    @Test
    public void testSAI() {
        // sendAuthenticationInfo
        sigfw.resetUnitTestingFlags();
        SccpDataMessage sccpDataMessage = sigfw.sccpStack.getSccpProvider().getMessageFactory().createDataMessageClass0(calledParty, callingParty, hexStringToByteArray("6516480433119839490402035ea26c08a106020102020138"), 0, true, null, null);
        sigfw.onMessage(sccpDataMessage);
        
        try {
            Thread.currentThread().sleep(100);
        } catch (InterruptedException ex) {
            Logger.getLogger(Test_SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        Assert.assertTrue("sendAuthenticationInfo message (opCode 56, TCAP Continue) should be allowed", sigfw.unitTestingFlags_sendSccpMessage);
    }
    
    @Test
    public void testUSSD() { 
        // processUnstructuredSSRequest
        sigfw.resetUnitTestingFlags();
        SccpDataMessage sccpDataMessage = sigfw.sccpStack.getSccpProvider().getMessageFactory().createDataMessageClass0(calledParty, callingParty, hexStringToByteArray("62754804000000016b432841060700118605010101a036603480020780a109060704000001001302be232821060704000001010101a016a01480099611111111111111f18107961111111111f16c28a12602010002013b301e04010f0410aa582ca65ac562b1582c168bc562b1118007911111111111f1"), 0, true, null, null);
        sigfw.onMessage(sccpDataMessage);
        
        try {
            Thread.currentThread().sleep(100);
        } catch (InterruptedException ex) {
            Logger.getLogger(Test_SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        Assert.assertTrue("processUnstructuredSSRequest message (opCode 59, TCAP Begin) should be allowed", sigfw.unitTestingFlags_sendSccpMessage);
    }
    
    @Test
    public void testCL() {
        // cancelLocation
        sigfw.resetUnitTestingFlags();
        SccpDataMessage sccpDataMessage = sigfw.sccpStack.getSccpProvider().getMessageFactory().createDataMessageClass0(calledParty, callingParty, hexStringToByteArray("623b4804000000036b1a2818060700118605010101a00d600ba1090607040000010002036c17a115020101020103a30d040811111111111111f10a0100"), 0, true, null, null);
        sigfw.onMessage(sccpDataMessage);
        
        try {
            Thread.currentThread().sleep(100);
        } catch (InterruptedException ex) {
            Logger.getLogger(Test_SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        Assert.assertTrue("cancelLocation message (opCode 3, TCAP Begin) should be blocked by Cat2", !sigfw.unitTestingFlags_sendSccpMessage);
    }
    
    @Test
    public void testPSI() {      
        // Provide Subscriber Info
        sigfw.resetUnitTestingFlags();
        SccpDataMessage sccpDataMessage = sigfw.sccpStack.getSccpProvider().getMessageFactory().createDataMessageClass0(calledParty, callingParty, hexStringToByteArray("623e4804000000466b1a2818060700118605010101a00d600ba109060704000001001c036c1aa1180201010201463010800811111111111111f1a20480008300"), 0, true, null, null);
        sigfw.onMessage(sccpDataMessage);
        
        try {
            Thread.currentThread().sleep(100);
        } catch (InterruptedException ex) {
            Logger.getLogger(Test_SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        Assert.assertTrue("provideSubscriberInfo message (opCode 70, TCAP Begin) should be blocked by Cat2", !sigfw.unitTestingFlags_sendSccpMessage);
    }
    
    @Test
    public void testPRN() {      
        // provideRoamingNumber
        sigfw.resetUnitTestingFlags();
        SccpDataMessage sccpDataMessage = sigfw.sccpStack.getSccpProvider().getMessageFactory().createDataMessageClass0(calledParty, callingParty, hexStringToByteArray("625d4804000000046b1a2818060700118605010101a00d600ba1090607040000010003026c39a137020101020104302f800811111111111111f18107111111111111f18207111111111111f1a5080a010104030401a0880791111111111111"), 0, true, null, null);
        sigfw.onMessage(sccpDataMessage);
        
        try {
            Thread.currentThread().sleep(100);
        } catch (InterruptedException ex) {
            Logger.getLogger(Test_SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        Assert.assertTrue("provideRoamingNumber message (opCode 4, TCAP Begin) should be blocked by Cat2", !sigfw.unitTestingFlags_sendSccpMessage);
    }

}
