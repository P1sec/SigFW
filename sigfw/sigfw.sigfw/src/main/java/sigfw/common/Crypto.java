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

import com.p1sec.sigfw.SigFW_interface.CryptoInterface;
import diameterfw.DiameterFirewall;
import static diameterfw.DiameterFirewall.VENDOR_ID;
import diameterfw.DiameterFirewallConfig;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
//import javafx.util.Pair;
import java.util.AbstractMap;
import java.util.Date;
import java.util.Random;
import java.util.SortedMap;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.X509KeyManager;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.jdiameter.api.Avp;
import org.jdiameter.api.AvpDataException;
import org.jdiameter.api.AvpSet;
import org.jdiameter.api.Message;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.mobicents.protocols.ss7.sccp.LongMessageRuleType;
import org.mobicents.protocols.ss7.sccp.impl.message.MessageFactoryImpl;
import org.mobicents.protocols.ss7.sccp.message.SccpDataMessage;
import org.mobicents.protocols.ss7.tcap.asn.ApplicationContextNameImpl;
import org.mobicents.protocols.ss7.tcap.asn.DialogPortion;
import org.mobicents.protocols.ss7.tcap.asn.DialogRequestAPDUImpl;
import org.mobicents.protocols.ss7.tcap.asn.EncodeException;
import org.mobicents.protocols.ss7.tcap.asn.InvokeImpl;
import org.mobicents.protocols.ss7.tcap.asn.OperationCodeImpl;
import org.mobicents.protocols.ss7.tcap.asn.TcapFactory;
import org.mobicents.protocols.ss7.tcap.asn.comp.Component;
import org.mobicents.protocols.ss7.tcap.asn.comp.ComponentType;
import org.mobicents.protocols.ss7.tcap.asn.comp.Invoke;
import org.mobicents.protocols.ss7.tcap.asn.comp.OperationCode;
import org.mobicents.protocols.ss7.tcap.asn.comp.Parameter;
import org.mobicents.protocols.ss7.tcap.asn.comp.TCBeginMessage;
import static sigfw.common.Utils.concatByteArray;
import static sigfw.common.Utils.int32ToBytes;
import static sigfw.common.Utils.bytesToInt32;
import static sigfw.common.Utils.splitByteArray;

/**
 *
 * @author Martin Kacer
 */
public class Crypto implements CryptoInterface {
    
    /*
    // Encryption RSA
    public static KeyFactory keyFactoryRSA;
    public static Cipher cipherRSA;
    public static Signature signatureRSA;
    // Encryption EC
    public static KeyFactory keyFactoryEC;
    public static Cipher cipherAES_GCM;
    public static Signature signatureECDSA;
    */
    
    static final public int AVP_ENCRYPTED = 1100;
    static final public int AVP_ENCRYPTED_GROUPED = 1101;
    static final public int AVP_ENCRYPTED_GROUPED_INDEXED = 1102;
    static final public int AVP_DESS_SIGNATURE = 1000;
    static final public int AVP_DESS_DIGITAL_SIGNATURE = 1001;
    static final public int AVP_DESS_SYSTEM_TIME = 1002;
    static final public int AVP_DESS_SIGNING_IDENTITY = 1003;
    static final public int AVP_DESS_DIGITAL_SIGNATURE_TYPE = 1004;
    static final public int ENUM_DESS_DIGITAL_SIGNATURE_TYPE_RSA_with_SHA256 = 0;
    static final public int ENUM_DESS_DIGITAL_SIGNATURE_TYPE_ECDSA_with_SHA256 = 1;
    static final public int ENUM_DESS_DIGITAL_SIGNATURE_TYPE_DSA_with_SHA256 = 2;
    
    static final public Long OC_SIGNATURE = 100L;
    static final public Long OC_ASYNC_ENCRYPTION = 95L;
    
    // Diameter signature and decryption time window used for TVP
    public final static long diameter_tvp_time_window = 30;  // in seconds
    
    // TCAP signature and decryption time window used for TVP
    private final static long tcap_tvp_time_window = 30;  // in seconds
    
    protected static final Logger logger = Logger.getLogger(Crypto.class);
    
    static Random randomGenerator = new Random();
    
    static {
        configLog4j();
    }
    
    public Crypto() {
        
        /*
        // Encryption RSA
        try {
            keyFactoryRSA = KeyFactory.getInstance("RSA");
            cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            signatureRSA = Signature.getInstance("SHA256WithRSA");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // Encryption EC
        try {
            keyFactoryEC = KeyFactory.getInstance("EC");
            cipherAES_GCM = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
            signatureECDSA = Signature.getInstance("SHA256withECDSA");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        */
    }
    
    protected static void configLog4j() {
       InputStream inStreamLog4j = Crypto.class.getClassLoader().getResourceAsStream("log4j.properties");
       Properties propertiesLog4j = new Properties();
       try {
           propertiesLog4j.load(inStreamLog4j);
           PropertyConfigurator.configure(propertiesLog4j);
       } catch (Exception e) {
           e.printStackTrace();
       }

       logger.debug("log4j configured");
    }

    @Override
    public void diameterSign(Message message, SortedMap<String, KeyPair> origin_realm_signing, SortedMap<String, String> origin_realm_signing_signing_realm, Map<String, SSLEngine> dtls_engine_permanent_client) {
        //logger.debug("Message Sign = " + message.getAvps().toString());
        
        Signature signature = null;       
        
        String orig_realm = "";
        Avp avp = message.getAvps().getAvp(Avp.ORIGIN_REALM);
        try {
            if (avp != null && avp.getDiameterURI() != null && avp.getDiameterURI().getFQDN() != null) {
                orig_realm = avp.getDiameterURI().getFQDN();
            }
        } catch (AvpDataException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        if (orig_realm.equals("")) {
            logger.warn("No Origin-Realm AVP detected");
            return;
        }
        
        String dest_realm = "";
        avp = message.getAvps().getAvp(Avp.DESTINATION_REALM);
        try {
            if (avp != null && avp.getDiameterURI() != null && avp.getDiameterURI().getFQDN() != null) {
                dest_realm = avp.getDiameterURI().getFQDN();
            }
        } catch (AvpDataException ex) {
            logger.warn("Missing or incorrect Dest-Realm AVP detected");
            return;
        }
        
        // Answers without Dest-Realm, but seen previously Request
        // TODO accessing public variable diameter_sessions in DiameterFirewall
        if (!message.isRequest() && dest_realm.equals("")) {
            String session_id = message.getApplicationId() + ":" + message.getCommandCode() + ":" + orig_realm + ":" + message.getEndToEndIdentifier();
            if (DiameterFirewall.diameter_sessions.containsKey(session_id)) {
                dest_realm = DiameterFirewall.diameter_sessions.get(session_id);
            }
        }
        
        
        String signingRealm = null;
        if (DiameterFirewallConfig.origin_realm_signing_signing_realm.containsKey(orig_realm)) {
           signingRealm = DiameterFirewallConfig.origin_realm_signing_signing_realm.get(orig_realm);
        }
        if (signingRealm == null) {
            // No SigningRealm for Origin-Realm in configuration means it is not required to sign this message
            return;
        }
        
        PrivateKey privateKey = null;
        // Try to check if there exist DTLS session and use they key from there
        if (dtls_engine_permanent_client != null) {
            if (dtls_engine_permanent_client.containsKey(dest_realm)) {
                //SSLEngine engine = dtls_engine_permanent_client.get(dest_realm);
                
                X509KeyManager km = (X509KeyManager)DiameterFirewall.kmf.getKeyManagers()[0];

                privateKey = km.getPrivateKey(DiameterFirewall.dtls_keyStoreAlias);
                //engine.getSession().getLocalCertificates()[0].
                //engine.getSSLParameters().

                logger.debug("diameterSign: SigFW DTLS key used (using key[0] from array of length " + DiameterFirewall.kmf.getKeyManagers().length + ")");
            }
        }
        // Try to get key from configuration 
        if (origin_realm_signing.containsKey(orig_realm) && privateKey == null) {
            KeyPair keyPair = origin_realm_signing.get(orig_realm);
            
            if (keyPair != null) {
                privateKey = keyPair.getPrivate();
            }
            
            logger.debug("diameterSign: SigFW config key used");
        }   
        
        if (privateKey == null) {
            logger.warn("No private key in diameterSign");
            return;
        }
        
                
        if(privateKey != null) {

            AvpSet _avps = message.getAvps();

            boolean signed = false;
            if (_avps.getAvp(AVP_DESS_SIGNATURE, VENDOR_ID) != null) {
                signed = true;
            }

            if (!signed) {

                // Add DESS_SIGNATURE grouped AVP
                AvpSet avps = _avps.addGroupedAvp(AVP_DESS_SIGNATURE, VENDOR_ID, false, false);

                // Add DESS_SIGNING_REALM inside
                avps.addAvp(AVP_DESS_SIGNING_IDENTITY, signingRealm.getBytes(), VENDOR_ID, false, false);

                // Add DESS_SYSTEM_TIME inside
                long t = System.currentTimeMillis();
                Date date = new Date(t);
                avps.addAvp(AVP_DESS_SYSTEM_TIME, date, VENDOR_ID, false, false);

                // Add AVP_DESS_DIGITAL_SIGNATURE_TYPE inside
                if (privateKey instanceof RSAPrivateKey) {
                    avps.addAvp(AVP_DESS_DIGITAL_SIGNATURE_TYPE, ENUM_DESS_DIGITAL_SIGNATURE_TYPE_RSA_with_SHA256, VENDOR_ID, false, false);
                }
                else if (privateKey instanceof ECPrivateKey) {
                    avps.addAvp(AVP_DESS_DIGITAL_SIGNATURE_TYPE, ENUM_DESS_DIGITAL_SIGNATURE_TYPE_ECDSA_with_SHA256, VENDOR_ID, false, false);
                }
                else if (privateKey instanceof DSAPrivateKey) {
                    avps.addAvp(AVP_DESS_DIGITAL_SIGNATURE_TYPE, ENUM_DESS_DIGITAL_SIGNATURE_TYPE_DSA_with_SHA256, VENDOR_ID, false, false);
                }

                // Add AVP_DESS_DIGITAL_SIGNATURE           
                try {       

                    String dataToSign = message.getApplicationId() + ":" + message.getCommandCode() + ":" + message.getEndToEndIdentifier();

                    // jDiameter AVPs are not ordered, and the order could be changed by DRAs in IPX, so order AVPs by sorting base64 strings
                    List<String> strings = new ArrayList<String>();
                    for (int i = 0; i < _avps.size(); i++) {
                        Avp a = _avps.getAvpByIndex(i);
                        if (a.getCode() != Avp.ROUTE_RECORD) {
                            strings.add(a.getCode() + "|" + Base64.getEncoder().encodeToString(a.getRawData()));
                        }
                    }
                    Collections.sort(strings);
                    for (String s : strings) {
                         dataToSign += ":" + s;
                    }


                    byte[] signatureBytes = null;
                    try {
                        // DSA
                        if (privateKey instanceof DSAPrivateKey) {
                            signature = Signature.getInstance("SHA256withDSA");
                        }
                        // RSA
                        else if (privateKey instanceof RSAPrivateKey) {
                            signature = Signature.getInstance("SHA256WithRSA");
                        }
                        // EC
                        else if (privateKey instanceof ECPrivateKey) {
                            signature = Signature.getInstance("SHA256withECDSA");
                        }
                        // Other
                        else {
                            _avps.removeAvp(AVP_DESS_SIGNATURE, VENDOR_ID);
                            logger.warn("Unknown Private Key algorithm: " + privateKey.getAlgorithm());
                            return;
                        }
                        
                        logger.debug("Creating signature ...");
                        logger.debug("Signature algorithm: " + signature.getAlgorithm());
                        logger.debug("PrivateKey algorithm: " + privateKey.getAlgorithm());
                        
                        signature.initSign(privateKey);

                        signature.update(dataToSign.getBytes());
                        signatureBytes = signature.sign();
                        
                    } catch (NoSuchAlgorithmException ex) {
                        java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                    }

                    logger.debug("Adding Diameter Signed Data: " + dataToSign);
                    logger.debug("Adding Diameter Signature: " + Base64.getEncoder().encodeToString(signatureBytes));

                    // Add AVP_DESS_SIGNATURE inside
                    avps.addAvp(AVP_DESS_DIGITAL_SIGNATURE, signatureBytes, VENDOR_ID, false, false);

                } catch (InvalidKeyException ex) {
                    _avps.removeAvp(AVP_DESS_SIGNATURE, VENDOR_ID);
                    java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                } catch (SignatureException ex) {
                    _avps.removeAvp(AVP_DESS_SIGNATURE, VENDOR_ID);
                    java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                }
            }        
        }
        
    }
    
    @Override
    public String diameterVerify(Message message, SortedMap<String, PublicKey> origin_realm_verify_signing_realm, Map<String, SSLEngine> dtls_engine_permanent_server) {
        logger.debug("Message Verify = " + message.getAvps().toString());
        
        if (origin_realm_verify_signing_realm == null) {
            return "";
        }
        
        Signature signature = null;
                      
        AvpSet _avps = message.getAvps();
        
        Avp _a = _avps.getAvp(AVP_DESS_SIGNATURE, VENDOR_ID);
        if (_a == null) {
            logger.debug("");
            return "DIAMETER FW: Missing DIAMETER signature (AVP_DESS_SIGNATURE).";
        }
        AvpSet avps = null;
        try {
            avps = _a.getGrouped();
        } catch (AvpDataException ex) {
            return "DIAMETER FW: Wrong DIAMETER signature. AVP_DESS_SIGNATURE is not grouped AVP.";
        }

        try {
            // Get AVP_DESS_SIGNING_IDENTITY
            String signing_realm = null;
            String orig_realm = null;

            Avp a_origin_realm = _avps.getAvp(Avp.ORIGIN_REALM);
            if (a_origin_realm != null && a_origin_realm.getDiameterURI() != null && a_origin_realm.getDiameterURI().getFQDN() != null) {
                orig_realm = a_origin_realm.getDiameterURI().getFQDN();
            }
            Avp a_signing_realm = avps.getAvp(AVP_DESS_SIGNING_IDENTITY, VENDOR_ID);
            if (a_signing_realm != null && a_signing_realm.getDiameterURI() != null && a_signing_realm.getDiameterURI().getFQDN() != null) {
                signing_realm = a_signing_realm.getDiameterURI().getFQDN();
            } else if (orig_realm != null) {
                signing_realm = orig_realm;
            } else {
                return "DIAMETER FW: Unable to verify message signature. Both AVP_DESS_SIGNING_REALM and ORIGIN_REALM are missing.";
            }
            //

            // Get AVP_DESS_SYSTEM_TIME
            Avp a_system_time = avps.getAvp(AVP_DESS_SYSTEM_TIME, VENDOR_ID);
            if (a_system_time == null) {
                return "DIAMETER FW: Invalid message signature. Missing AVP_DESS_SYSTEM_TIME.";
            }
            //

            // Get AVP_DESS_DIGITAL_SIGNATURE_TYPE
            Avp a_signature_type = avps.getAvp(AVP_DESS_DIGITAL_SIGNATURE_TYPE, VENDOR_ID);
            if (a_signature_type == null) {
                return "DIAMETER FW: Invalid message signature. Missing AVP_DESS_DIGITAL_SIGNATURE_TYPE.";
            }
            //
            
            // Get AVP_DESS_DIGITAL_SIGNATURE
            Avp a_digital_signature = avps.getAvp(AVP_DESS_DIGITAL_SIGNATURE, VENDOR_ID);
            if (a_digital_signature == null) {
                return "DIAMETER FW: Invalid message signature. Missing AVP_DESS_DIGITAL_SIGNATURE.";
            }
            
            // Remove the AVP_DESS_DIGITAL_SIGNATURE now
            // to not include it later in the signature calculation in the dataToSign array
            avps.removeAvp(AVP_DESS_DIGITAL_SIGNATURE, VENDOR_ID);   
            //
            

            // Verify timestamp
            Date date = a_system_time.getTime();

            byte[] signatureBytes = null;
            
            // ---- Verify Timestamp ----
            if (date != null) {
                long t = System.currentTimeMillis();
                
                long t_received = date.getTime();
                
                if (Math.abs(t_received-t) > diameter_tvp_time_window*1000) {
                    return "DIAMETER FW: DIAMETER verify signature. Wrong timestamp in TVP (received: " + t_received + ", current: " + t + ")";
                }              
            }
            // ---- End of Verify Timestamp ----

            // Verify Signature
            signatureBytes = a_digital_signature.getOctetString();

            String dataToSign = message.getApplicationId() + ":" + message.getCommandCode() + ":" + message.getEndToEndIdentifier();

            // jDiameter AVPs are not ordered, so order AVPs by sorting base64 strings
            List<String> strings = new ArrayList<String>();
            for (int i = 0; i < _avps.size(); i++) {
                Avp a = _avps.getAvpByIndex(i);
                if (a.getCode() != Avp.ROUTE_RECORD) {
                    strings.add(a.getCode() + "|" + Base64.getEncoder().encodeToString(a.getRawData()));
                }
            }
            Collections.sort(strings);
            for (String s : strings) {
                 dataToSign += ":" + s;
            }
            
            // remove all signature components from the message
            _avps.removeAvp(AVP_DESS_SIGNATURE, VENDOR_ID);                  

            PublicKey publicKey = null;
            
            // Try to check if there exist DTLS session and use they key from there
            if (dtls_engine_permanent_server != null && orig_realm != null) {
                if (dtls_engine_permanent_server.containsKey(orig_realm)) {
                    SSLEngine engine = dtls_engine_permanent_server.get(orig_realm);

                    try {
                        if (engine.getSession().getPeerCertificates() != null) {
                            Certificate cert = engine.getSession().getPeerCertificates()[0];
                            publicKey = cert.getPublicKey();
                        }
                    } catch (SSLPeerUnverifiedException ex) {
                        java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                    }

                    logger.debug("diameterVerify: SigFW DTLS key used (using dtls_engine_permanent_server.get(" + orig_realm + "))");
                }
            }
            // Try to get key from configuration 
            if (origin_realm_verify_signing_realm != null && orig_realm != null && publicKey == null) {
                publicKey = origin_realm_verify_signing_realm.get(orig_realm + ":" + signing_realm);
                
                logger.debug("diameterVerify: SigFW config key used");
            }
            
            if (publicKey == null) {
                logger.warn("DIAMETER FW: Missing Public Key, could not verify inbound message. Accepting message.");
                return "";
            }
            
            try {
                if (publicKey instanceof DSAPublicKey) {
                    
                    if (a_signature_type.getInteger32() != ENUM_DESS_DIGITAL_SIGNATURE_TYPE_DSA_with_SHA256) {
                        logger.warn("Configured Public Key type mismatch with type received in AVP_DESS_DIGITAL_SIGNATURE_TYPE");
                        return "DIAMETER FW: Wrong DIAMETER signature, type mismatch";
                    }
                    
                    signature = Signature.getInstance("SHA256WithDSA");

                } else if (publicKey instanceof RSAPublicKey) {

                    if (a_signature_type.getInteger32() != ENUM_DESS_DIGITAL_SIGNATURE_TYPE_RSA_with_SHA256) {
                        logger.warn("Configured Public Key type mismatch with type received in AVP_DESS_DIGITAL_SIGNATURE_TYPE");
                        return "DIAMETER FW: Wrong DIAMETER signature, type mismatch";
                    }
                    
                    signature = Signature.getInstance("SHA256WithRSA");

                } else if (publicKey instanceof ECPublicKey) {
                    
                    if (a_signature_type.getInteger32() != ENUM_DESS_DIGITAL_SIGNATURE_TYPE_ECDSA_with_SHA256) {
                        logger.warn("Configured Public Key type mismatch with type received in AVP_DESS_DIGITAL_SIGNATURE_TYPE");
                        return "DIAMETER FW: Wrong DIAMETER signature, type mismatch";
                    }
                    
                    signature = Signature.getInstance("SHA256withECDSA");
                } else {
                    logger.warn("Unknown Public Key algorithm: " + publicKey.getAlgorithm());
                    return "DIAMETER FW: Wrong DIAMETER signature, unknown type";
                }
            } catch (NoSuchAlgorithmException ex) {
                java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            if (signature == null) {
                logger.warn("DIAMETER FW: Internal error. Signature instance is null, could not verify inbound message. Accepting message.");
                return "";
            }
            
            logger.debug("Verification of signature ...");
            logger.debug("Signature algorithm: " + signature.getAlgorithm());
            logger.debug("PublicKey algorithm: " + publicKey.getAlgorithm());
            
            logger.debug("Verifying Diameter Signed Data: " + dataToSign);
            logger.debug("Verifying Diameter Signature: " + Base64.getEncoder().encodeToString(signatureBytes));
            
            signature.initVerify(publicKey);
            signature.update(dataToSign.getBytes());
            if (signatureBytes != null && signature.verify(signatureBytes)) {
                return "";
            }

        } catch (InvalidKeyException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (AvpDataException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        //}
        
        return "DIAMETER FW: Wrong DIAMETER signature";
    }

    @Override
    public void diameterEncrypt(Message message, PublicKey publicKey) throws InvalidKeyException {
        
        // Encryption RSA
        Cipher cipherRSA = null;
        // Encryption EC
        Cipher cipherAES_GCM = null;
        
        // Encryption RSA
        try {
            cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // Encryption EC
        try {
            cipherAES_GCM = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        
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
                
                if (publicKey instanceof RSAPublicKey) {
                    try {
                        //byte[] d = a.getRawData();
                        byte [] d = Utils.encodeAvp(a);

                        // SPI(version) and TVP(timestamp)
                        byte[] SPI = {0x00, 0x00, 0x00, 0x00};  // TODO
                        byte[] TVP = {0x00, 0x00, 0x00, 0x00};

                        long t = System.currentTimeMillis()/100;    // in 0.1s
                        TVP[0] = (byte) ((t >> 24) & 0xFF);
                        TVP[1] = (byte) ((t >> 16) & 0xFF);
                        TVP[2] = (byte) ((t >>  8) & 0xFF);
                        TVP[3] = (byte) ((t >>  0) & 0xFF);

                        //Crypto.cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey);
                        //byte[] cipherText = Crypto.cipherRSA.doFinal(b);

                        RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
                        cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey);

                        int keyLength = rsaPublicKey.getModulus().bitLength() / 8;

                        byte[][] datas = splitByteArray(d, keyLength - 11 - 4);
                        byte[] cipherText = null;
                        for (byte[] b : datas) {
                            cipherText = concatByteArray(cipherText, cipherRSA.doFinal(concatByteArray(TVP, b)));
                        }

                        cipherText = concatByteArray(SPI, cipherText);

                        //logger.debug("Add AVP Encrypted. Current index = " + i);
                        avps.insertAvp(i, AVP_ENCRYPTED, cipherText, VENDOR_ID, false, true);

                        avps.removeAvpByIndex(i + 1);

                    } catch (IllegalBlockSizeException ex) {
                        java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (BadPaddingException ex) {
                        java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                    }
                } else if (publicKey instanceof ECPublicKey) {
                    logger.warn("EC algorithm not implemented");
                    return;
                } else {
                    logger.warn("Unknown Public Key algorithm");
                    return;
                }
            }
        }
    }

    @Override
    public String diameterDecrypt(Message message, KeyPair keyPair) {
        
        // Encryption RSA
        Cipher cipherRSA = null;
        // Encryption EC
        Cipher cipherAES_GCM = null;
        
        // Encryption RSA
        try {
            cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // Encryption EC
        try {
            cipherAES_GCM = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        //logger.debug("== diameterDecrypt ==");
        AvpSet avps = message.getAvps();
        
        int avps_size = avps.size();
        
        
        for (int i = 0; i < avps_size; i++) {
            Avp a = avps.getAvpByIndex(i);
            
            //logger.debug("AVP[" + i + "] Code = " + a.getCode());
            
            if (a.getCode() == AVP_ENCRYPTED && a.isVendorId() && a.getVendorId() == VENDOR_ID) {
                logger.debug("Diameter Decryption of Encrypted AVP");
                    
                PrivateKey privateKey = keyPair.getPrivate();
                
                if (privateKey instanceof RSAPrivateKey) {
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

                        cipherRSA.init(Cipher.DECRYPT_MODE, privateKey);

                        RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
                        int keyLength = rsaPublicKey.getModulus().bitLength() / 8;

                        byte[][] datas = splitByteArray(d, keyLength/* - 11*/);
                        byte[] decryptedText = null;
                        for (byte[] _b : datas) {
                            d = cipherRSA.doFinal(_b);

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

                        //avps.insertAvp(i, ByteBuffer.wrap(cc).order(ByteOrder.BIG_ENDIAN).getInt(), d, false, false);

                        AvpImpl _a = (AvpImpl)Utils.decodeAvp(decryptedText);
                        avps.insertAvp(i, _a.getCode(), _a.getRawData(), _a.vendorID, _a.isMandatory, _a.isEncrypted);

                        avps.removeAvpByIndex(i + 1);

                    } catch (InvalidKeyException ex) {
                        java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IllegalBlockSizeException ex) {
                        java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (BadPaddingException ex) {
                        java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (AvpDataException ex) {
                        java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IOException ex) {
                        java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }  else if (privateKey instanceof ECPrivateKey) {
                    logger.warn("EC algorithm not implemented");
                    return "";
                } else {
                    logger.warn("Unknown Private Key algorithm");
                    return "";
                }
            } else if (a.getCode() == AVP_ENCRYPTED_GROUPED && a.isVendorId() && a.getVendorId() == VENDOR_ID) {
                logger.debug("Diameter Decryption of Grouped Encrypted AVP");
                
                PrivateKey privateKey = keyPair.getPrivate();
                   
                if (privateKey instanceof RSAPrivateKey) {
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

                        cipherRSA.init(Cipher.DECRYPT_MODE, privateKey);

                        RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
                        int keyLength = rsaPublicKey.getModulus().bitLength() / 8;

                        byte[][] datas = splitByteArray(d, keyLength/* - 11*/);
                        byte[] decryptedText = null;
                        for (byte[] _b : datas) {
                            d = cipherRSA.doFinal(_b);

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

                        //avps.insertAvp(i, ByteBuffer.wrap(cc).order(ByteOrder.BIG_ENDIAN).getInt(), d, false, false);

                        //logger.debug("decryptedText = " + decryptedText.toString());
                        //logger.debug("decryptedText.size = " + decryptedText.length);
                        AvpSetImpl _avps = (AvpSetImpl)Utils.decodeAvpSet(decryptedText, 0);

                        //logger.debug("SIZE = " + _avps.size());

                        for (int j = 0; j < _avps.size(); j++) {
                            AvpImpl _a = (AvpImpl)_avps.getAvpByIndex(j);
                            //logger.debug("addAVP = " + _a.getCode());
                            avps.insertAvp(i, _a.getCode(), _a.getRawData(), _a.vendorID, _a.isMandatory, _a.isEncrypted);
                        }
                        avps.removeAvpByIndex(i + _avps.size());

                    } catch (InvalidKeyException ex) {
                        //java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                        logger.warn("diameterDecrypt InvalidKeyException");
                    } catch (IllegalBlockSizeException ex) {
                        //java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                        logger.warn("diameterDecrypt IllegalBlockSizeException");
                    } catch (BadPaddingException ex) {
                        //java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                        logger.warn("diameterDecrypt BadPaddingException");
                    } catch (AvpDataException ex) {
                        //java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                        logger.warn("diameterDecrypt AvpDataException");
                    } catch (IOException ex) {
                        //java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                        logger.warn("diameterDecrypt IOException");
                    } catch (IllegalStateException ex) {
                        //java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                        logger.warn("diameterDecrypt IllegalStateException");
                    }
                }  else if (privateKey instanceof ECPrivateKey) {
                    logger.warn("EC algorithm not implemented");
                    return "";
                } else {
                    logger.warn("Unknown Private Key algorithm");
                    return "";
                }
            } else if (a.getCode() == AVP_ENCRYPTED_GROUPED_INDEXED && a.isVendorId() && a.getVendorId() == VENDOR_ID) {
                logger.warn("Diameter Decryption of Grouped Indexed Encrypted AVP is not supported by this SigFW version");
                return "";
            }
            
        }
        
        return "";
    }
            
    /**
     * Method to encrypt Diameter message v2
     * 
     * @param message Diameter message which will be encrypted
     * @param publicKey Public Key used for message encryption
     */
    public void diameterEncrypt_v2(Message message, PublicKey publicKey) throws InvalidKeyException {
        
        // Encryption RSA
        Cipher cipherRSA = null;
        // Encryption EC
        Cipher cipherAES_GCM = null;
        
        // Encryption RSA
        try {
            cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // Encryption EC
        try {
            cipherAES_GCM = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        //logger.debug("== diameterEncrypt_v2 ==");
        AvpSet avps = message.getAvps();
        
        AvpSet erAvp = avps.addGroupedAvp(AVP_ENCRYPTED_GROUPED, VENDOR_ID, false, true);
        
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
        
        if (publicKey instanceof RSAPublicKey) {
            try {
                //byte[] d = a.getRawData();
                byte [] d = Utils.encodeAvpSet(erAvp);

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

                //Crypto.cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey);
                //byte[] cipherText = Crypto.cipherRSA.doFinal(b);

                RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
                cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey);

                int keyLength = rsaPublicKey.getModulus().bitLength() / 8;

                byte[][] datas = splitByteArray(d, keyLength - 11 - 4);
                byte[] cipherText = null;
                for (byte[] b : datas) {
                    cipherText = concatByteArray(cipherText, cipherRSA.doFinal(concatByteArray(TVP, b)));
                }

                cipherText = concatByteArray(SPI, cipherText);

                //logger.debug("Add AVP Grouped Encrypted. Current index");
                avps.removeAvp(AVP_ENCRYPTED_GROUPED, VENDOR_ID);
                avps.addAvp(AVP_ENCRYPTED_GROUPED, cipherText, VENDOR_ID, false, true);

            } catch (IllegalBlockSizeException ex) {
                //java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                logger.warn("diameterEncrypt_v2 IllegalBlockSizeException");
            } catch (BadPaddingException ex) {
                //java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                logger.warn("diameterEncrypt_v2 BadPaddingException");
            } catch (IllegalStateException ex) {
                //java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                logger.warn("diameterEncrypt_v2 IllegalStateException");
            }
        }  else if (publicKey instanceof ECPublicKey) {
            logger.warn("EC Public Key algorithm not implemented");
            return;
        } else {
            logger.warn("Unknown Public Key algorithm");
            return;
        }
    }
    
    /**
     * Method to encrypt Diameter message v3
     * 
     * @param message Diameter message which will be encrypted
     * @param publicKey Public Key used for message encryption
     */
    public void diameterEncrypt_v3(Message message, PublicKey publicKey) throws InvalidKeyException {
        
        logger.warn("diameterEncrypt_v3 is not supported by this SigFW version");
        return;
  
    }

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
    @Override
    public int tcapVerify(SccpDataMessage message, TCBeginMessage tcb, Component[] comps, PublicKey publicKey) {
        
        logger.debug("tcapVerify for SCCP Called GT = " + message.getCalledPartyAddress().getGlobalTitle().getDigits());
        
        Signature signatureRSA = null;
        Signature signatureECDSA = null;
        
        // Encryption RSA
        try {
            signatureRSA = Signature.getInstance("SHA256WithRSA");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // Encryption EC
        try {
            signatureECDSA = Signature.getInstance("SHA256withECDSA");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // --------------- TCAP verify  ---------------
        int signature_ok = 0;

        List<Integer> signed_index = new ArrayList<Integer>();
        for (int i = 0; i < comps.length; i++) {
            // find all signature components
            if (comps[i].getType() == ComponentType.Invoke) {
                Invoke inv = (Invoke) comps[i];
                if (inv.getOperationCode().getLocalOperationCode() == OC_SIGNATURE) {
                    signed_index.add(i);
                }
            }
        }
        if (signed_index.size() > 0) {
            // read signature component
            InvokeImpl invSignature = (InvokeImpl)comps[signed_index.get(0)];
            Parameter p = invSignature.getParameter();
            Parameter[] pa;

            // Signature
            byte[] signatureBytes = null;
            long t_tvp = 0;

            if (p != null && p.getTagClass() == Tag.CLASS_UNIVERSAL) {
                pa = p.getParameters();


                // Reserved (currently not used) - Signature Version
                // TODO
                if (pa.length >= 1) {

                }

                // TVP
                if (pa.length >= 2) {
                    byte[] TVP = {0x00, 0x00, 0x00, 0x00};
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

                    TVP = pa[1].getData();
                    for (int i = 0; i < TVP.length; i++) {
                        t_tvp =  ((t_tvp << 8) + (TVP[i] & 0xff));
                    }
                    if (Math.abs(t_tvp-t) > tcap_tvp_time_window*10) {
                        logger.info("TCAP FW: TCAP verify signature. Wrong timestamp in TVP (received: " + t_tvp + ", current: " + t + ")");
                        return 0;
                    }
                    // ---- End of Verify TVP ----
                }

                // Signature
                if (pa.length >= 3) {
                    if (pa[2].getTagClass() == Tag.CLASS_PRIVATE && pa[2].getTag() == Tag.STRING_OCTET) {
                        signatureBytes = pa[2].getData();
                    }
                }
            }

            // remove all signature components
            Component[] c = new Component[comps.length - signed_index.size()];
            for (int i = 0; i < comps.length - signed_index.size(); i++) {
                if (!signed_index.contains(i)) {
                    c[i] = comps[i];
                }
            }

            tcb.setComponent(c);
            AsnOutputStream aos = new AsnOutputStream();
            try {
                tcb.encode(aos);
            } catch (EncodeException ex) {
                java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
            }

            byte[] _d = aos.toByteArray();
            message.setData(_d);
            String dataToSign = "";

            // verify signature
            try {
                comps = c;
                dataToSign = message.getCallingPartyAddress().getGlobalTitle().getDigits()
                        + message.getCalledPartyAddress().getGlobalTitle().getDigits() + t_tvp;
                for (int i = 0; i < comps.length; i++) {
                    AsnOutputStream _aos = new AsnOutputStream();
                    try {
                        comps[i].encode(_aos);
                        dataToSign += Base64.getEncoder().encodeToString(_aos.toByteArray());
                    } catch (EncodeException ex) {
                        java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

                if (publicKey instanceof RSAPublicKey) {
                    signatureRSA.initVerify(publicKey);
                    signatureRSA.update(dataToSign.getBytes());
                    if (signatureBytes != null && signatureRSA.verify(signatureBytes)) {
                        signature_ok = 1;
                    }
                } else if (publicKey instanceof ECPublicKey) {
                    logger.warn("EC Public Key algorithm not implemented");
                    signature_ok = 0;
                } else {
                    logger.warn("Unknown Public Key algorithm");
                    signature_ok = 0;
                }

            } catch (InvalidKeyException ex) {
                java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SignatureException ex) {
                java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
            }

            logger.debug("Removing TCAP Signed Data: " + dataToSign);
            if (signatureBytes != null) {
                logger.debug("Removing TCAP Signature: " + Base64.getEncoder().encodeToString(signatureBytes));
            }
        }
        return signature_ok;
        // --------------------------------------------
    }

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
    @Override
    public LongMessageRuleType tcapSign(SccpDataMessage message, TCBeginMessage tcb, Component[] comps, LongMessageRuleType lmrt, KeyPair keyPair) {
        
        Signature signatureRSA = null;
        Signature signatureECDSA = null;
        
        // Encryption RSA
        try {
            signatureRSA = Signature.getInstance("SHA256WithRSA");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // Encryption EC
        try {
            signatureECDSA = Signature.getInstance("SHA256withECDSA");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        

        // --------------- TCAP signing ---------------
        LongMessageRuleType l = lmrt;
        
        PrivateKey privateKey = keyPair.getPrivate();

        Component[] c = new Component[comps.length + 1];
        int i;
        boolean signed = false;
        for (i = 0; i < comps.length; i++) {
            c[i] = comps[i];
            // already signed check
            if (c[i].getType() == ComponentType.Invoke) {
                Invoke inv = (Invoke) comps[i];
                if (inv.getOperationCode().getLocalOperationCode() == OC_SIGNATURE) {
                    signed = true;
                }
            }
        }
        if (!signed) {
            c[i] = new InvokeImpl();
            ((InvokeImpl)c[i]).setInvokeId(1l);
            OperationCode oc = TcapFactory.createOperationCode();
            oc.setLocalOperationCode(OC_SIGNATURE);
            ((InvokeImpl)c[i]).setOperationCode(oc);

            // Reserved (currently not used) - Signature Version
            // TODO
            Parameter p1 = TcapFactory.createParameter();
            p1.setTagClass(Tag.CLASS_PRIVATE);
            p1.setPrimitive(true);
            p1.setTag(Tag.STRING_OCTET);
            p1.setData("v1".getBytes());

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

            Parameter p2 = TcapFactory.createParameter();
            p2.setTagClass(Tag.CLASS_PRIVATE);
            p2.setPrimitive(true);
            p2.setTag(Tag.STRING_OCTET);
            p2.setData(TVP);               

            // Signature
            Parameter p3 = TcapFactory.createParameter();
            p3.setTagClass(Tag.CLASS_PRIVATE);
            p3.setPrimitive(true);
            p3.setTag(Tag.STRING_OCTET);

            try {
                String dataToSign = message.getCallingPartyAddress().getGlobalTitle().getDigits()
                        + message.getCalledPartyAddress().getGlobalTitle().getDigits() + t_tvp;
                for (i = 0; i < comps.length; i++) {
                    AsnOutputStream _aos = new AsnOutputStream();
                    try {
                        comps[i].encode(_aos);
                        dataToSign += Base64.getEncoder().encodeToString(_aos.toByteArray());
                    } catch (EncodeException ex) {
                        java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

                byte[] signatureBytes = null;
                // RSA
                if (privateKey instanceof RSAPrivateKey) {
                    signatureRSA.initSign(privateKey);

                    signatureRSA.update(dataToSign.getBytes());
                    signatureBytes = signatureRSA.sign();
                }
                // EC
                else if (privateKey instanceof ECPrivateKey) {
                    logger.warn("EC Public Key algorithm not implemented");
                    return l;
                } else {
                    logger.warn("Unknown Private Key algorithm");
                    return l;
                }
                
                logger.debug("Adding TCAP Signed Data: " + dataToSign);
                logger.debug("Adding TCAP Signature: " + Base64.getEncoder().encodeToString(signatureBytes));

                p3.setData(signatureBytes);

                Parameter p = TcapFactory.createParameter();
                p.setTagClass(Tag.CLASS_UNIVERSAL);
                p.setTag(0x04);
                p.setParameters(new Parameter[] {p1, p2, p3});

                ((InvokeImpl)c[i]).setParameter(p);
                tcb.setComponent(c);
                AsnOutputStream aos = new AsnOutputStream();
                try {
                    tcb.encode(aos);
                } catch (EncodeException ex) {
                    java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                }

                byte[] _d = aos.toByteArray();
                message.setData(_d);

            } catch (InvalidKeyException ex) {
                java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SignatureException ex) {
                java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        return l;
        // --------------------------------------------
    }
    
    /**
     * Method to encrypt TCAP message.
     * 
     * 
     * @param message SCCP message
     * @param sccpMessageFactory SCCP message factory
     * @param publicKey Public Key
     * @param lmrt Long Message Rule Type, if UDT or XUDT should be send
     * @return AbstractMap.SimpleEntry<message, lmrt> - message and indicator if UDT or XUDT should be send
     */    
    @Override
    public AbstractMap.SimpleEntry<SccpDataMessage, LongMessageRuleType> tcapEncrypt(SccpDataMessage message, MessageFactoryImpl sccpMessageFactory, PublicKey publicKey, LongMessageRuleType lmrt) {
        logger.debug("TCAP Encryption for SCCP Called GT = " + message.getCalledPartyAddress().getGlobalTitle().getDigits());
        
        // Encryption RSA
        Cipher cipherRSA = null;
        // Encryption EC
        Cipher cipherAES_GCM = null;
        
        // Encryption RSA
        try {
            cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // Encryption EC
        try {
            cipherAES_GCM = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        LongMessageRuleType l = lmrt;
        
        try {
            
            // Sending XUDT message from UDT message

            // SPI(version) and TVP(timestamp)
            byte[] SPI = {0x00, 0x00, 0x00, 0x00};  // TODO
            byte[] TVP = {0x00, 0x00, 0x00, 0x00};

            long t = System.currentTimeMillis()/100;    // in 0.1s
            TVP[0] = (byte) ((t >> 24) & 0xFF);
            TVP[1] = (byte) ((t >> 16) & 0xFF);
            TVP[2] = (byte) ((t >>  8) & 0xFF);
            TVP[3] = (byte) ((t >>  0) & 0xFF);

            if (publicKey instanceof RSAPublicKey) {
                RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
                cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey);

                int keyLength = rsaPublicKey.getModulus().bitLength() / 8;

                byte[][] datas = splitByteArray(message.getData(), keyLength - 11 - 4);
                byte[] cipherText = null;
                for (byte[] b : datas) {
                    cipherText = concatByteArray(cipherText, cipherRSA.doFinal(concatByteArray(TVP, b)));
                }

                cipherText = concatByteArray(SPI, cipherText);
                
                
                TCBeginMessage tc = TcapFactory.createTCBeginMessage();

                byte[] otid = { (byte)randomGenerator.nextInt(256), (byte)randomGenerator.nextInt(256), (byte)randomGenerator.nextInt(256), (byte)randomGenerator.nextInt(256) };

                tc.setOriginatingTransactionId(otid);
                // Create Dialog Portion
                DialogPortion dp = TcapFactory.createDialogPortion();

                dp.setOid(true);
                dp.setOidValue(new long[] { 0, 0, 17, 773, 1, 1, 1 });

                dp.setAsn(true);

                DialogRequestAPDUImpl diRequestAPDUImpl = new DialogRequestAPDUImpl();

                // TODO change Application Context
                ApplicationContextNameImpl acn = new ApplicationContextNameImpl();
                acn.setOid(new long[] { 0, 4, 0, 0, 1, 0, 19, 2 });

                diRequestAPDUImpl.setApplicationContextName(acn);
                diRequestAPDUImpl.setDoNotSendProtocolVersion(true);

                dp.setDialogAPDU(diRequestAPDUImpl);

                tc.setDialogPortion(dp);

                Component[] c = new Component[1];

                c[0] = new InvokeImpl();
                ((InvokeImpl)c[0]).setInvokeId(1l);
                OperationCode oc = TcapFactory.createOperationCode();
                oc.setLocalOperationCode(OC_ASYNC_ENCRYPTION);
                ((InvokeImpl)c[0]).setOperationCode(oc);

                // DATA
                Parameter p1 = TcapFactory.createParameter();
                p1.setTagClass(Tag.CLASS_PRIVATE);
                p1.setPrimitive(true);
                p1.setTag(Tag.STRING_OCTET);
                p1.setData(cipherText);

                // Encrypted data
                Parameter _p = TcapFactory.createParameter();
                _p.setTagClass(Tag.CLASS_UNIVERSAL);
                _p.setTag(0x04);
                _p.setParameters(new Parameter[] { p1 });
                ((InvokeImpl)c[0]).setParameter(_p);
        
                tc.setComponent(c);
                AsnOutputStream aos = new AsnOutputStream();
                try {
                    tc.encode(aos);
                } catch (EncodeException ex) {
                    java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                }

                byte[] _d = aos.toByteArray();
                

                SccpDataMessage m = sccpMessageFactory.createDataMessageClass0(message.getCalledPartyAddress(), message.getCallingPartyAddress(), _d, message.getOriginLocalSsn(), false, null, null);
                message = m;
                l = LongMessageRuleType.XUDT_ENABLED;
            } else if (publicKey instanceof ECPublicKey) {
                logger.warn("EC algorithm not implemented");
                return new AbstractMap.SimpleEntry<>(message, l);
            } else {
                logger.warn("Unknown Public Key algorithm");
                return new AbstractMap.SimpleEntry<>(message, l);
            }
        } catch (InvalidKeyException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new AbstractMap.SimpleEntry<>(message, l);
    }
    
    
    /**
     * Method to decrypt TCAP message.
     * 
     * 
     * @param message SCCP message
     * @param comps TCAP components
     * @param sccpMessageFactory SCCP message factory
     * @param keyPair Key Pair
     * @return AbstractMap.SimpleEntry<message, result> - message and result indicator
     */    
    public AbstractMap.SimpleEntry<SccpDataMessage, String> tcapDecrypt(SccpDataMessage message, Component[] comps, MessageFactoryImpl sccpMessageFactory, KeyPair keyPair) {
        logger.debug("TCAP Decryption for SCCP Called GT = " + message.getCalledPartyAddress().getGlobalTitle().getDigits());

        // Encryption RSA
        Cipher cipherRSA = null;
        // Encryption EC
        Cipher cipherAES_GCM = null;
        
        // Encryption RSA
        try {
            cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // Encryption EC
        try {
            cipherAES_GCM = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        try {
            byte[] data = message.getData();
            
            AsnInputStream ais = new AsnInputStream(data);
            
            // this should have TC message tag
            int tag;
            try {
                tag = ais.readTag();
            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                logger.warn("Unknown TCAP tag detected in tcapDecrypt");
                return new AbstractMap.SimpleEntry<>(message, "Unknown TCAP tag detected");
            }
            
            for (Component comp : comps) {
                if (comp == null) {
                    continue;
                }

                byte[] message_data = null;
                OperationCodeImpl oc;

                switch (comp.getType()) {
                case Invoke:
                    Invoke inv = (Invoke) comp;
                       
                    Parameter p = inv.getParameter();
                    Parameter[] params = p.getParameters();
                    
                    if (params != null && params.length >= 1) {

                        // Encrypted data
                        Parameter p1 = params[0];
                        message_data = p1.getData();
                    }


                    // Sending XUDT message from UDT message

                    // SPI(version) and TVP(timestamp)
                    byte[] SPI = {0x00, 0x00, 0x00, 0x00};
                    byte[] TVP = {0x00, 0x00, 0x00, 0x00};

                    if (message_data.length >= SPI.length) {
                        SPI = Arrays.copyOfRange(message_data, 0, SPI.length);
                        data = Arrays.copyOfRange(message_data, SPI.length, message_data.length);
                    } else {
                        data = message_data;
                    }

                    PrivateKey privateKey = keyPair.getPrivate();

                    if (privateKey instanceof RSAPrivateKey) {

                        cipherRSA.init(Cipher.DECRYPT_MODE, privateKey);

                        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
                        int keyLength = rsaPublicKey.getModulus().bitLength() / 8;

                        // TODO verify SPI
                        byte[][] datas = splitByteArray(data, keyLength/* - 11*/);
                        byte[] decryptedText = null;
                        for (byte[] b : datas) {

                            byte[] d = cipherRSA.doFinal(b);
                            // ------- Verify TVP --------
                            long t = System.currentTimeMillis() / 100;    // in 0.1s
                            TVP[0] = (byte) ((t >> 24) & 0xFF);
                            TVP[1] = (byte) ((t >> 16) & 0xFF);
                            TVP[2] = (byte) ((t >> 8) & 0xFF);
                            TVP[3] = (byte) ((t >> 0) & 0xFF);
                            t = 0;
                            for (int i = 0; i < TVP.length; i++) {
                                t = ((t << 8) + (TVP[i] & 0xff));
                            }

                            TVP[0] = d[0];
                            TVP[1] = d[1];
                            TVP[2] = d[2];
                            TVP[3] = d[3];
                            long t_tvp = 0;
                            for (int i = 0; i < TVP.length; i++) {
                                t_tvp = ((t_tvp << 8) + (TVP[i] & 0xff));
                            }
                            if (Math.abs(t_tvp - t) > tcap_tvp_time_window * 10) {
                                return new AbstractMap.SimpleEntry<>(message, "SS7 FW: Blocked in decryption, Wrong timestamp in TVP (received: " + t_tvp + ", current: " + t + ")");
                            }
                            d = Arrays.copyOfRange(d, TVP.length, d.length);
                            // ---- End of Verify TVP ----

                            decryptedText = concatByteArray(decryptedText, d);

                            SccpDataMessage m = sccpMessageFactory.createDataMessageClass0(message.getCalledPartyAddress(), message.getCallingPartyAddress(), decryptedText, message.getOriginLocalSsn(), false, null, null);
                            message = m;
                        }
                    }  else if (privateKey instanceof ECPrivateKey) {
                        logger.warn("EC algorithm not implemented");
                        return new AbstractMap.SimpleEntry<>(message, "");
                    } else {
                        logger.warn("Unknown Private Key algorithm");
                        return new AbstractMap.SimpleEntry<>(message, "");
                    }

                
                
                break;
                }
            }
            
        } catch (InvalidKeyException ex) {
            logger.info("TCAP FW: TCAP decryption failed for SCCP Called GT: " + message.getCalledPartyAddress().getGlobalTitle().getDigits() + " InvalidKeyException: " + ex.getMessage());
            //java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            logger.info("TCAP FW: TCAP decryption failed for SCCP Called GT: " + message.getCalledPartyAddress().getGlobalTitle().getDigits() + " IllegalBlockSizeException: " + ex.getMessage());
            //java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            logger.info("TCAP FW: TCAP decryption failed for SCCP Called GT: " + message.getCalledPartyAddress().getGlobalTitle().getDigits() + " BadPaddingException: " + ex.getMessage());
            //java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new AbstractMap.SimpleEntry<>(message, "");
    }
}
