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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import com.jayway.jsonpath.ReadContext;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.SortedMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 *
 * @author Martin Kacer
 * 
 * Class handling the firewall configuration file and storing the firewall ACLs
 * 
 * 
 */
public class DiameterFirewallConfig {
    public enum FirewallPolicy {
        DROP_SILENTLY,
        DROP_WITH_DIAMETER_ERROR,
        DNAT_TO_HONEYPOT,
        ALLOW
    }
    
    static ReadContext jsonConf;
    static JSONObject jsonConfObject;
    public static SortedMap<String, String> diameter_origin_realm_blacklist;
    public static SortedMap<String, String> diameter_application_id_whitelist;
    public static SortedMap<String, String> diameter_command_code_blacklist;
    public static SortedMap<String, String> hplmn_imsi;
    public static SortedMap<String, String> hplmn_realms;
    public static SortedMap<String, String> diameter_cat2_command_code_blacklist;
    public static SortedMap<Integer, String> lua_blacklist_rules;
    public static SortedMap<String, PublicKey> destination_realm_encryption;
    public static SortedMap<String, KeyPair> destination_realm_decryption;
    public static String encryption_autodiscovery = "false";
    public static SortedMap<String, PublicKey> origin_realm_verify;
    public static SortedMap<String, KeyPair> origin_realm_signing;
    public static FirewallPolicy firewallPolicy = FirewallPolicy.DROP_SILENTLY;
    public static String honeypot_diameter_host = "";
    public static String honeypot_diameter_realm = "";
    public static int honeypot_dnat_session_expiration_timeout = 15;
    public static String mthreat_salt = "";
    
    // Encryption RSA
    public static KeyFactory keyFactoryRSA;
    public static Cipher cipherRSA;
    public static Signature signatureRSA;
    // Encryption EC
    public static KeyFactory keyFactoryEC;
    public static Cipher cipherAES_GCM;
    public static Signature signatureECDSA;
    
    public static <T extends Object> T get(String jp) {
        return jsonConf.read(jp);
    }
    
    /**
     * Main class used for testing
     * @param args
     */
    public static void main(String[] args) {
        System.out.println("*************************************");
        System.out.println("***    SignalingFirewallConfig    ***");
        System.out.println("*************************************");
        
        
        try {
            loadConfigFromFile("sigfw.json.last");
        } catch (Exception ex) {
            try {
                loadConfigFromFile("sigfw.json");
            } catch (IOException ex1) {
                Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex1);
            } catch (ParseException ex1) {
                Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex1);
            }
        }
        
        try {
            saveConfigToFile("sigfw.json.last");
        } catch (FileNotFoundException ex) {
            Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    /**
     * Returns sub map from SortedMap, where keys match the prefix
     */
    private static <V> SortedMap<String, V> filterPrefix(SortedMap<String,V> baseMap, String prefix) {
        if(prefix.length() > 0) {
            char nextLetter = (char)(prefix.charAt(prefix.length() -1) + 1);
            String end = prefix.substring(0, prefix.length()-1) + nextLetter;
            return baseMap.subMap(prefix, end);
        }
        return baseMap;
    }
    
    /**
     * Returns true if value is found in SortedMap, including also simple wildcard *
     */
    private static <V> boolean simpleWildcardCheck(SortedMap<String,V> baseMap, String value) {
        if (value == null) {
            return false;
        }
        
        if (baseMap.get(value) != null) {
            //System.out.println("======= " + value);
            return true;
        } else if (value.length() > 0){
            String v = value;
            v = v.substring(0, v.length() - 1);
                
            while (v.length() > 0) {
                char nextLetter = (char)(v.charAt(v.length() -1) + 1);
                String end = v.substring(0, v.length()-1) + nextLetter;
                SortedMap<String, V> b = baseMap.subMap(v, end);
                
                for (String key : b.keySet()) {
                    if ((key.length() == v.length() + 1) && key.endsWith("*")) {
                        //System.out.println("======= " + key);
                        return true;
                    }
                }
                
                v = v.substring(0, v.length() - 1);
            }        
        }   
      return false;
    }
    
    /**
     * Load and parse the configuration json and feed the internal values
     * @param filename
     * @throws java.io.FileNotFoundException
     * @throws java.io.IOException
     * @throws org.json.simple.parser.ParseException
     */
    public static void loadConfigFromFile(String filename) throws FileNotFoundException, IOException, ParseException {
        
        // Encryption RSA
        try {
            keyFactoryRSA = KeyFactory.getInstance("RSA");
            cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            signatureRSA = Signature.getInstance("SHA256WithRSA");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // Encryption EC
        try {
            keyFactoryEC = KeyFactory.getInstance("EC");
            cipherAES_GCM = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
            signatureECDSA = Signature.getInstance("SHA256withECDSA");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        JSONParser parser = new JSONParser();
        jsonConfObject = (JSONObject)parser.parse(new FileReader(filename));
        
        
        String json = new Scanner(new File(filename)).useDelimiter("\\Z").next();
        //System.out.println(json);
        
        jsonConf = JsonPath.parse(json);
        
        String firewall_policy = DiameterFirewallConfig.get("$.sigfw_configuration.firewall_rules.firewall_policy");
        //System.out.println("firewall_policy = " + firewall_policy);     
        if (firewall_policy.equals("DROP_SILENTLY")) {
            firewallPolicy = FirewallPolicy.DROP_SILENTLY;
        } else if (firewall_policy.equals("DROP_WITH_DIAMETER_ERROR")) {
            firewallPolicy = FirewallPolicy.DROP_WITH_DIAMETER_ERROR;
        } else if (firewall_policy.equals("DNAT_TO_HONEYPOT")) {
            firewallPolicy = FirewallPolicy.DNAT_TO_HONEYPOT;
            
            honeypot_diameter_host = DiameterFirewallConfig.get("$.sigfw_configuration.firewall_rules.honeypot.diameter_host");
            honeypot_diameter_realm = DiameterFirewallConfig.get("$.sigfw_configuration.firewall_rules.honeypot.diameter_realm");
            honeypot_dnat_session_expiration_timeout = Integer.parseInt((String)DiameterFirewallConfig.get("$.sigfw_configuration.firewall_rules.honeypot.dnat_session_expiration_timeout"));
            
            
        } else if (firewall_policy.equals("ALLOW")) {
            firewallPolicy = FirewallPolicy.ALLOW;
        }
        //System.out.println("firewall_policy_enum = " + firewallPolicy.toString());    
        
        
        List<String> origin_realm_blacklist = DiameterFirewallConfig.get("$.sigfw_configuration.firewall_rules.diameter.origin_realm_blacklist");
        //sccp_calling_gt_blacklist = new ConcurrentHashMap();
        diameter_origin_realm_blacklist = new ConcurrentSkipListMap<String, String>();
        for (final String s : origin_realm_blacklist) {
            diameter_origin_realm_blacklist.put(s, ""); 
        }

        List<String> application_id_whitelist = DiameterFirewallConfig.get("$.sigfw_configuration.firewall_rules.diameter.application_id_whitelist");
        diameter_application_id_whitelist = new ConcurrentSkipListMap<String, String>();
        for (final String s : application_id_whitelist) {
            diameter_application_id_whitelist.put(s, ""); 
        }
        
        List<String> command_code_blacklist = DiameterFirewallConfig.get("$.sigfw_configuration.firewall_rules.diameter.command_code_blacklist");
        diameter_command_code_blacklist = new ConcurrentSkipListMap<String, String>();
        for (final String s : command_code_blacklist) {
            diameter_command_code_blacklist.put(s, ""); 
        }
        
        List<String> imsi = DiameterFirewallConfig.get("$.operator_configuration.Home_IMSI_prefixes");
        hplmn_imsi = new ConcurrentSkipListMap<String, String>();
        for (final String s : imsi) {
            hplmn_imsi.put(s, ""); 
        }
        
        List<String> realms = DiameterFirewallConfig.get("$.operator_configuration.Home_Diameter_Realm_list");
        hplmn_realms = new ConcurrentSkipListMap<String, String>();
        for (final String s : realms) {
            hplmn_realms.put(s, "");
        }
        
        List<String> cat2_oc_blacklist = DiameterFirewallConfig.get("$.sigfw_configuration.firewall_rules.diameter.cat2_command_code_blacklist");
        diameter_cat2_command_code_blacklist = new ConcurrentSkipListMap<String, String>();
        for (final String s : cat2_oc_blacklist) {
            diameter_cat2_command_code_blacklist.put(s, ""); 
        }
        
        List<String> blacklist_rules = DiameterFirewallConfig.get("$.sigfw_configuration.firewall_rules.lua.blacklist_rules");
        lua_blacklist_rules = new ConcurrentSkipListMap<Integer, String>();
        int k = 0;
        for (final String s : blacklist_rules) {
            lua_blacklist_rules.put(k, s);
            k++;
        }
        
        // ------------------------------------
        // Encryption
        destination_realm_encryption = new ConcurrentSkipListMap<String, PublicKey>();
        try {
            List<Map<String, Object>> _destination_realm_encryption = DiameterFirewallConfig.get("$.sigfw_configuration.encryption_rules.destination_realm_encryption");
            for (int i = 0; i < _destination_realm_encryption.size(); i++) {
                String destination_realm = (String)_destination_realm_encryption.get(i).get("destination_realm");
                if (destination_realm != null) {
                    
                    PublicKey publicKey = null;
                    byte[] publicKeyBytes =  Base64.getDecoder().decode((String)_destination_realm_encryption.get(i).get("public_key"));
                    String publicKeyType = (String)_destination_realm_encryption.get(i).get("public_key_type");
                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                    
                    if (publicKeyType.equals("RSA")) {
                        publicKey = keyFactoryRSA.generatePublic(pubKeySpec);
                    } else if (publicKeyType.equals("EC")) {
                        publicKey = keyFactoryEC.generatePublic(pubKeySpec);
                    }
                    destination_realm_encryption.put(destination_realm, publicKey);
                }
            }
        } catch (InvalidKeySpecException ex) {
           Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        destination_realm_decryption = new ConcurrentSkipListMap<String, KeyPair>();
        try {
            List<Map<String, Object>> _destination_realm_decryption = DiameterFirewallConfig.get("$.sigfw_configuration.encryption_rules.destination_realm_decryption");
            for (int i = 0; i < _destination_realm_decryption.size(); i++) {
                String destination_realm = (String)_destination_realm_decryption.get(i).get("destination_realm");
                if (destination_realm != null) {
                    
                    PrivateKey privateKey = null;
                    byte[] privateKeyBytes =  Base64.getDecoder().decode((String)_destination_realm_decryption.get(i).get("private_key"));
                    String privateKeyType = (String)_destination_realm_decryption.get(i).get("private_key_type");
                    PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                    
                    if (privateKeyType.equals("RSA")) {
                        privateKey = keyFactoryRSA.generatePrivate(privKeySpec);
                    } else if (privateKeyType.equals("EC")) {
                        privateKey = keyFactoryEC.generatePrivate(privKeySpec);
                    }
                    
                    PublicKey publicKey = null;
                    byte[] publicKeyBytes =  Base64.getDecoder().decode((String)_destination_realm_decryption.get(i).get("public_key"));
                    String publicKeyType = (String)_destination_realm_decryption.get(i).get("public_key_type");
                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                    
                    if (publicKeyType.equals("RSA")) {
                        publicKey = keyFactoryRSA.generatePublic(pubKeySpec);
                    } else if (publicKeyType.equals("EC")) {
                        publicKey = keyFactoryEC.generatePublic(pubKeySpec);
                    }
                    
                    KeyPair keypair = new KeyPair(publicKey, privateKey);
                    destination_realm_decryption.put(destination_realm, keypair);
                }
            }
        } catch (InvalidKeySpecException ex) {
           Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        encryption_autodiscovery = (String)DiameterFirewallConfig.get("$.sigfw_configuration.encryption_rules.autodiscovery");
            
        // ------------------------------------
        // ------------------------------------
        // Signing
        origin_realm_verify = new ConcurrentSkipListMap<String, PublicKey>();
        try {
            List<Map<String, Object>> _origin_realm_verify = DiameterFirewallConfig.get("$.sigfw_configuration.signature_rules.origin_realm_verify");
            for (int i = 0; i < _origin_realm_verify.size(); i++) {
                String origin_realm = (String)_origin_realm_verify.get(i).get("origin_realm");
                if (origin_realm != null) {
                    
                    PublicKey publicKey = null;
                    byte[] publicKeyBytes =  Base64.getDecoder().decode((String)_origin_realm_verify.get(i).get("public_key"));
                    String publicKeyType = (String)_origin_realm_verify.get(i).get("public_key_type");
                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                    
                    if (publicKeyType.equals("RSA")) {
                        publicKey = keyFactoryRSA.generatePublic(pubKeySpec);
                    } else if (publicKeyType.equals("EC")) {
                        publicKey = keyFactoryEC.generatePublic(pubKeySpec);
                    }
                    origin_realm_verify.put(origin_realm, publicKey);
                }
            }
        } catch (InvalidKeySpecException ex) {
           Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        origin_realm_signing = new ConcurrentSkipListMap<String, KeyPair>();
        try {
            List<Map<String, Object>> _origin_realm_signing = DiameterFirewallConfig.get("$.sigfw_configuration.signature_rules.origin_realm_signing");
            for (int i = 0; i < _origin_realm_signing.size(); i++) {
                String origin_realm = (String)_origin_realm_signing.get(i).get("origin_realm");
                if (origin_realm != null) {
                    
                    PrivateKey privateKey = null;
                    byte[] privateKeyBytes =  Base64.getDecoder().decode((String)_origin_realm_signing.get(i).get("private_key"));
                    String privateKeyType = (String)_origin_realm_signing.get(i).get("private_key_type");
                    PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                    
                    if (privateKeyType.equals("RSA")) {
                        privateKey = keyFactoryRSA.generatePrivate(privKeySpec);
                    } else if (privateKeyType.equals("EC")) {
                        privateKey = keyFactoryEC.generatePrivate(privKeySpec);
                    }
                    
                    PublicKey publicKey = null;
                    byte[] publicKeyBytes =  Base64.getDecoder().decode((String)_origin_realm_signing.get(i).get("public_key"));
                    String publicKeyType = (String)_origin_realm_signing.get(i).get("public_key_type");
                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                    
                    if (publicKeyType.equals("RSA")) {
                        publicKey = keyFactoryRSA.generatePublic(pubKeySpec);
                    } else if (publicKeyType.equals("EC")) {
                        publicKey = keyFactoryEC.generatePublic(pubKeySpec);
                    }
                    
                    KeyPair keypair = new KeyPair(publicKey, privateKey);
                    origin_realm_signing.put(origin_realm, keypair);
                }
            }
        } catch (InvalidKeySpecException ex) {
           Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        // ------------------------------------
        
        try {
            mthreat_salt = (String)DiameterFirewallConfig.get("$.sigfw_configuration.firewall_rules.mthreat.mthreat_salt");
        } catch (PathNotFoundException ex) {
            //Logger.getLogger(DiameterFirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    /**
     * Save configuration to json
     * @param filename
     * @throws java.io.FileNotFoundException
     */
    public static void saveConfigToFile(String filename) throws FileNotFoundException {
        
        JSONObject j = (JSONObject) jsonConfObject.get("sigfw_configuration");
        j = (JSONObject) j.get("firewall_rules");
        JSONObject diameter = (JSONObject) j.get("diameter");
        JSONArray origin_realm_blacklist = (JSONArray) diameter.get("origin_realm_blacklist");
        origin_realm_blacklist.clear();
        for (String key : diameter_origin_realm_blacklist.keySet()) {
            origin_realm_blacklist.add(key);
        }
        
        JSONArray application_id_whitelist = (JSONArray) diameter.get("application_id_whitelist");
        application_id_whitelist.clear();
        for (String key : diameter_application_id_whitelist.keySet()) {
            application_id_whitelist.add(key);
        }
        
        JSONArray command_code_blacklist = (JSONArray) diameter.get("command_code_blacklist");
        command_code_blacklist.clear();
        for (String key : diameter_command_code_blacklist.keySet()) {
            command_code_blacklist.add(key);
        }
        
        try {         
            FileWriter file = new FileWriter(filename);
            //file.write(jsonConfObject.toJSONString());
            
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            String jsonOutput = gson.toJson(jsonConfObject);
            file.write(jsonOutput);

            file.flush();
            file.close();
 
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    
    /**
     * Public method to verify if Diameter Origin Realm is on blacklist
     * @param s
     * @return 
     */
    public static boolean check_diameter_origin_realm_blacklist(String s) {
        if (diameter_origin_realm_blacklist.get(s) != null) {
            return true;
        }
        return false;
    }
    
    /**
     * Public method to verify if Diameter Application ID is on whitelist
     * @param s
     * @return 
     */
    public static boolean check_diameter_application_id_whitelist(String s) {
        if (diameter_application_id_whitelist.get(s) != null) {
            return true;
        }
        return false;
    }
    
    /**
     * Public method to verify if Diameter Command Code is on blacklist
     * @param s
     * @return 
     */
    public static boolean check_diameter_command_code_blacklist(String s) {
        if (diameter_command_code_blacklist.get(s) != null) {
            return true;
        }
        return false;
    }
    
}
