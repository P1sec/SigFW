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
package com.p1sec.sigfw.SigFW_interface;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
//import javafx.util.Pair;
import java.util.AbstractMap;
import org.jdiameter.api.Message;
import org.mobicents.protocols.ss7.sccp.LongMessageRuleType;
import org.mobicents.protocols.ss7.sccp.impl.message.MessageFactoryImpl;
import org.mobicents.protocols.ss7.sccp.message.SccpDataMessage;
import org.mobicents.protocols.ss7.tcap.asn.comp.Component;
import org.mobicents.protocols.ss7.tcap.asn.comp.TCBeginMessage;

/**
 *
 * @author Martin Kacer
 */
public interface CryptoInterface {
    
    /**
     * Method to sign Diameter message
     * 
     * @param message Diameter message which will be signed
     * @param keyPair KeyPair used to sign message
     */
    public void diameterSign(Message message, KeyPair keyPair, String signingRealm);
    
    /**
     * Method to verify the Diameter message signature
     * 
     * 
     * @param message Diameter message which will be verified
     * @param publicKey Public Key used to verify message signature
     * @return result, empty string if successful, otherwise error message
     */
    public String diameterVerify(Message message, PublicKey publicKey);
 
    
    /**
     * Method to encrypt Diameter message
     * 
     * @param message Diameter message which will be encrypted
     * @param publicKey Public Key used for message encryption
     */
    public void diameterEncrypt(Message message, PublicKey publicKey) throws InvalidKeyException;
    public void diameterEncrypt_v2(Message message, PublicKey publicKey) throws InvalidKeyException;
    public void diameterEncrypt_v3(Message message, PublicKey publicKey) throws InvalidKeyException;
    
    /**
     * Method to decrypt Diameter message
     * 
     * @param message Diameter message which will be decrypted
     * @param keyPair Key Pair used for message encryption
     * @return result, empty string if successful, otherwise error message
     */
    public String diameterDecrypt(Message message, KeyPair keyPair);
    
    /**
     * Method remove from SCCP message duplicated TCAP signatures and verifies the TCAP signature.
     * Method currently is designed only for TCAP begin messages.
     * 
     * 
     * @param message SCCP message
     * @param tcb TCAP Begin Message
     * @param comps TCAP Components
     * @param publicKey Public Key
     * @return -1 no public key to verify signature, 0 signature does not match, 1 signature ok
     */
    public int tcapVerify(SccpDataMessage message, TCBeginMessage tcb, Component[] comps, PublicKey publicKey);
    
    /**
     * Method to add TCAP signature into SCCP message.
     * Method currently is designed only for TCAP begin messages.
     * 
     * 
     * @param message SCCP message
     * @param tcb TCAP Begin Message
     * @param comps TCAP Components
     * @param lmrt Long Message Rule Type, if UDT or XUDT should be send
     * @param keyPair Key Pair
     * @return Long Message Rule Type, if UDT or XUDT should be send
     */
    LongMessageRuleType tcapSign(SccpDataMessage message, TCBeginMessage tcb, Component[] comps, LongMessageRuleType lmrt, KeyPair keyPair);

    /**
     * Method to encrypt TCAP message.
     * 
     * 
     * @param message SCCP message
     * @param sccpMessageFactory SCCP message factory
     * @param publicKey Public Key
     * @param lmrt Long Message Rule Type, if UDT or XUDT should be send
     * @return pair<message, lmrt> - message and indicator if UDT or XUDT should be send
     */    
    public AbstractMap.SimpleEntry<SccpDataMessage, LongMessageRuleType> tcapEncrypt(SccpDataMessage message, MessageFactoryImpl sccpMessageFactory, PublicKey publicKey, LongMessageRuleType lmr);
    
    /**
     * Method to decrypt TCAP message.
     * 
     * 
     * @param message SCCP message
     * @param sccpMessageFactory SCCP message factory
     * @param keyPair Key Pair
     * @return pair<message, result> - message and result indicator
     */    
    public AbstractMap.SimpleEntry<SccpDataMessage, String> tcapDecrypt(SccpDataMessage message, MessageFactoryImpl sccpMessageFactory, KeyPair keyPair);
}
