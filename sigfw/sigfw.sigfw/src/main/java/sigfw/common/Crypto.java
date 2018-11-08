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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import javafx.util.Pair;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.jdiameter.api.Avp;
import org.jdiameter.api.AvpDataException;
import org.jdiameter.api.AvpSet;
import org.jdiameter.api.Message;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.mobicents.protocols.ss7.sccp.LongMessageRuleType;
import org.mobicents.protocols.ss7.sccp.impl.message.MessageFactoryImpl;
import org.mobicents.protocols.ss7.sccp.message.SccpDataMessage;
import org.mobicents.protocols.ss7.tcap.asn.EncodeException;
import org.mobicents.protocols.ss7.tcap.asn.InvokeImpl;
import org.mobicents.protocols.ss7.tcap.asn.TcapFactory;
import org.mobicents.protocols.ss7.tcap.asn.comp.Component;
import org.mobicents.protocols.ss7.tcap.asn.comp.ComponentType;
import org.mobicents.protocols.ss7.tcap.asn.comp.Invoke;
import org.mobicents.protocols.ss7.tcap.asn.comp.OperationCode;
import org.mobicents.protocols.ss7.tcap.asn.comp.Parameter;
import org.mobicents.protocols.ss7.tcap.asn.comp.TCBeginMessage;
import static sigfw.common.Utils.concatByteArray;
import static sigfw.common.Utils.splitByteArray;
import ss7fw.SS7Firewall;
import ss7fw.SS7FirewallConfig;

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
    
    static final private int AVP_ENCRYPTED = 1100;
    static final private int AVP_ENCRYPTED_GROUPED = 1101;
    static final private int AVP_SIGNATURE = 1000;
    
    static final private Long OC_SIGNATURE = 100L;
    
    // Diameter signature and decryption time window used for TVP
    private final static long diameter_tvp_time_window = 30;  // in seconds
    
    // TCAP signature and decryption time window used for TVP
    private final static long tcap_tvp_time_window = 30;  // in seconds
    
    protected static final Logger logger = Logger.getLogger(Crypto.class);
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
    public void diameterSign(Message message, KeyPair keyPair) {
        //logger.debug("Message Sign = " + message.getAvps().toString());
        
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
                        
                        String dataToSign = message.getApplicationId() + ":" + message.getCommandCode() + ":" + message.getEndToEndIdentifier() + ":" + t_tvp;

                        // jDiameter AVPs are not ordered, and the order could be changed by DRAs in IPX, so order AVPs by sorting base64 strings
                        List<String> strings = new ArrayList<String>();
                        for (int i = 0; i < avps.size(); i++) {
                            Avp a = avps.getAvpByIndex(i);
                            if (a.getCode() != Avp.ROUTE_RECORD) {
                                strings.add(a.getCode() + "|" + Base64.getEncoder().encodeToString(a.getRawData()));
                            }
                        }
                        Collections.sort(strings);
                        for (String s : strings) {
                             dataToSign += ":" + s;
                        }

                        /*for (int i = 0; i < avps.size(); i++) {
                            Avp a = avps.getAvpByIndex(i);
                            if (a.getCode() != Avp.ROUTE_RECORD) {
                                dataToSign += ":" + Base64.getEncoder().encodeToString(a.getRawData());
                            }
                        }*/

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
                            return;
                        } else {
                            logger.warn("Unknown Private Key algorithm");
                            return;
                        }

                        logger.debug("Adding Diameter Signed Data: " + dataToSign);
                        logger.debug("Adding Diameter Signature: " + Base64.getEncoder().encodeToString(signatureBytes));

                        avps.addAvp(AVP_SIGNATURE, concatByteArray(VER, concatByteArray(TVP, signatureBytes)));

                    } catch (InvalidKeyException ex) {
                        java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (SignatureException ex) {
                        java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }        
            }
        }
    }
    
    @Override
    public String diameterVerify(Message message, PublicKey publicKey) {
        //logger.debug("Message Verify = " + message.getAvps().toString());
        
        if (publicKey == null) {
            return "";
        }
        
        Signature signatureRSA = null;
        Signature signatureECDSA = null;
        
        // Encryption RSA
        try {
            signatureRSA = Signature.getInstance("SHA256WithRSA");
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
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
                    if (a.getCode() != Avp.ROUTE_RECORD) {
                        strings.add(a.getCode() + "|" + Base64.getEncoder().encodeToString(a.getRawData()));
                    }
                }
                Collections.sort(strings);
                for (String s : strings) {
                     dataToSign += ":" + s;
                }

                /*for (int i = 0; i < avps.size(); i++) {
                    Avp a = avps.getAvpByIndex(i);
                    if (a.getCode() != Avp.ROUTE_RECORD) {
                        dataToSign += ":" + Base64.getEncoder().encodeToString(a.getRawData());
                    }
                }*/
                
                if (publicKey instanceof RSAPublicKey) {
                    signatureRSA.initVerify(publicKey);
                    signatureRSA.update(dataToSign.getBytes());
                    if (signatureBytes != null && signatureRSA.verify(signatureBytes)) {
                        return "";
                    }
                } else if (publicKey instanceof ECPublicKey) {
                    logger.warn("EC Public Key algorithm not implemented");
                    return "";
                } else {
                    logger.warn("Unknown Public Key algorithm");
                    return "";
                }

            } catch (InvalidKeyException ex) {
                java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SignatureException ex) {
                java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
            } catch (AvpDataException ex) {
                java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
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
                        avps.insertAvp(i, AVP_ENCRYPTED, cipherText, false, false);

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
            
            if (a.getCode() == AVP_ENCRYPTED) {
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
                        avps.insertAvp(i, _a.getCode(), _a.getRawData(), _a.vendorID, _a.isMandatory, false);

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
            } else if (a.getCode() == AVP_ENCRYPTED_GROUPED) {
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
                            avps.insertAvp(i, _a.getCode(), _a.getRawData(), _a.vendorID, _a.isMandatory, false);
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
                avps.removeAvp(AVP_ENCRYPTED_GROUPED);
                avps.addAvp(AVP_ENCRYPTED_GROUPED, cipherText, false, false);

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
     * @return pair<message, lmrt> - message and indicator if UDT or XUDT should be send
     */    
    @Override
    public Pair<SccpDataMessage, LongMessageRuleType> tcapEncrypt(SccpDataMessage message, MessageFactoryImpl sccpMessageFactory, PublicKey publicKey, LongMessageRuleType lmrt) {
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

                SccpDataMessage m = sccpMessageFactory.createDataMessageClass0(message.getCalledPartyAddress(), message.getCallingPartyAddress(), cipherText, message.getOriginLocalSsn(), false, null, null);
                message = m;
                l = LongMessageRuleType.XUDT_ENABLED;
            } else if (publicKey instanceof ECPublicKey) {
                logger.warn("EC algorithm not implemented");
                return new Pair<>(message, lmrt);
            } else {
                logger.warn("Unknown Public Key algorithm");
                return new Pair<>(message, lmrt);
            }
        } catch (InvalidKeyException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new Pair<>(message, lmrt);
    }
    
    
    /**
     * Method to decrypt TCAP message.
     * 
     * 
     * @param message SCCP message
     * @param sccpMessageFactory SCCP message factory
     * @param keyPair Key Pair
     * @return pair<message, result> - message and result indicator
     */    
    public Pair<SccpDataMessage, String> tcapDecrypt(SccpDataMessage message, MessageFactoryImpl sccpMessageFactory, KeyPair keyPair) {
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
            // Sending XUDT message from UDT message

            // SPI(version) and TVP(timestamp)
            byte[] SPI = {0x00, 0x00, 0x00, 0x00};
            byte[] TVP = {0x00, 0x00, 0x00, 0x00};

            byte[] data = null;
            if (message.getData().length >= SPI.length) {
                SPI = Arrays.copyOfRange(message.getData(), 0, SPI.length);
                data = Arrays.copyOfRange(message.getData(), SPI.length, message.getData().length);
            } else {
                data = message.getData();
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
                        return new Pair<>(message, "SS7 FW: Blocked in decryption, Wrong timestamp in TVP (received: " + t_tvp + ", current: " + t + ")");
                    }
                    d = Arrays.copyOfRange(d, TVP.length, d.length);
                    // ---- End of Verify TVP ----

                    decryptedText = concatByteArray(decryptedText, d);
                    
                    SccpDataMessage m = sccpMessageFactory.createDataMessageClass0(message.getCalledPartyAddress(), message.getCallingPartyAddress(), decryptedText, message.getOriginLocalSsn(), false, null, null);
                    message = m;
                }
            }  else if (privateKey instanceof ECPrivateKey) {
                logger.warn("EC algorithm not implemented");
                return new Pair<>(message, ""); 
            } else {
                logger.warn("Unknown Private Key algorithm");
                return new Pair<>(message, ""); 
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
        return new Pair<>(message, "");         
    }
}
