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
package ss7fw;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import com.jayway.jsonpath.ReadContext;
import diameterfw.DiameterFirewallConfig;
import static diameterfw.DiameterFirewallConfig.cipherAES_GCM;
import static diameterfw.DiameterFirewallConfig.cipherRSA;
import static diameterfw.DiameterFirewallConfig.destination_realm_encryption;
import static diameterfw.DiameterFirewallConfig.keyFactoryEC;
import static diameterfw.DiameterFirewallConfig.keyFactoryRSA;
import static diameterfw.DiameterFirewallConfig.signatureECDSA;
import static diameterfw.DiameterFirewallConfig.signatureRSA;
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


public class SS7FirewallConfig {
    public enum FirewallPolicy {
        DROP_SILENTLY,
        DROP_WITH_SCCP_ERROR,
        DNAT_TO_HONEYPOT,
        ALLOW
    }
    
    static ReadContext jsonConf;
    static JSONObject jsonConfObject;
    public static List<String> m3ua_server_remote_pc;
    public static List<String> m3ua_client_remote_pc;
    public static SortedMap<String, String> sccp_calling_gt_whitelist;
    public static SortedMap<String, String> sccp_calling_gt_blacklist;
    public static SortedMap<String, String> tcap_oc_blacklist;
    public static SortedMap<String, String> hplmn_imsi;
    public static SortedMap<String, String> hplmn_gt;
    public static SortedMap<String, String> map_cat2_oc_blacklist;
    public static SortedMap<Integer, String> lua_blacklist_rules;
    public static SortedMap<String, PublicKey> called_gt_encryption;
    public static SortedMap<String, KeyPair> called_gt_decryption;
    public static String encryption_autodiscovery = "false";
    public static SortedMap<String, PublicKey> calling_gt_verify;
    public static SortedMap<String, KeyPair> calling_gt_signing;
    public static FirewallPolicy firewallPolicy = FirewallPolicy.DROP_SILENTLY;
    public static String honeypot_sccp_gt = "";
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
                Logger.getLogger(SS7FirewallConfig.class.getName()).log(Level.SEVERE, null, ex1);
            } catch (ParseException ex1) {
                Logger.getLogger(SS7FirewallConfig.class.getName()).log(Level.SEVERE, null, ex1);
            }
        }
        
        try {
            saveConfigToFile("sigfw.json.last");
        } catch (FileNotFoundException ex) {
            Logger.getLogger(SS7FirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
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
     * Returns Key if value is found in SortedMap, including also simple wildcard *
     */
    public static <V> String simpleWildcardKeyFind(SortedMap<String,V> baseMap, String value) {
        if (value == null) {
            return null;
        }
        
        if (baseMap.get(value) != null) {
            //System.out.println("======= " + value);
            return value;
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
                        return key;
                    }
                }
                
                v = v.substring(0, v.length() - 1);
            }        
        }   
        return null;
    }
    
    /**
     * Returns true if value is found in SortedMap, including also simple wildcard *
     */
    public static <V> boolean simpleWildcardCheck(SortedMap<String,V> baseMap, String value) {
        
        String key = simpleWildcardKeyFind(baseMap, value);
        if (key != null) {
            return true;
        }
        
        return false;
        
    }
    
    /**
     * Returns Value if value is found in SortedMap, including also simple wildcard *
     */
    public static <V> V simpleWildcardFind(SortedMap<String,V> baseMap, String value) {
        String key = simpleWildcardKeyFind(baseMap, value);
        if (key != null) {
            return baseMap.get(key);
        }
        
        return null;

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
            Logger.getLogger(SS7FirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(SS7FirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
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
        
        m3ua_server_remote_pc = SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_server.remote_pc");
        m3ua_client_remote_pc = SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_client.remote_pc");
        
        List<String> calling_gt_whitelist = SS7FirewallConfig.get("$.sigfw_configuration.firewall_rules.sccp.calling_gt_whitelist");
        //sccp_calling_gt_blacklist = new ConcurrentHashMap();
        sccp_calling_gt_whitelist = new ConcurrentSkipListMap<String, String>();
        for (final String s : calling_gt_whitelist) {
            sccp_calling_gt_whitelist.put(s, ""); 
        }
        
        List<String> calling_gt_blacklist = SS7FirewallConfig.get("$.sigfw_configuration.firewall_rules.sccp.calling_gt_blacklist");
        //sccp_calling_gt_blacklist = new ConcurrentHashMap();
        sccp_calling_gt_blacklist = new ConcurrentSkipListMap<String, String>();
        for (final String s : calling_gt_blacklist) {
            sccp_calling_gt_blacklist.put(s, ""); 
        }
        //System.out.println(simpleWildcardCheck(sccp_calling_gt_blacklist, "2222242"));
        //for(Map.Entry<String,String> entry : filterPrefix(sccp_calling_gt_blacklist, "22212342").entrySet()) {
        //    System.out.println(entry.getKey());
        //}
        //System.out.println("sccp_calling_gt_blacklist size = " + sccp_calling_gt_blacklist.size());     
        
        String firewall_policy = SS7FirewallConfig.get("$.sigfw_configuration.firewall_rules.firewall_policy");
        //System.out.println("firewall_policy = " + firewall_policy);     
        if (firewall_policy.equals("DROP_SILENTLY")) {
            firewallPolicy = FirewallPolicy.DROP_SILENTLY;
        } else if (firewall_policy.equals("DROP_WITH_SCCP_ERROR")) {
            firewallPolicy = FirewallPolicy.DROP_WITH_SCCP_ERROR;
        } else if (firewall_policy.equals("DNAT_TO_HONEYPOT")) {
            firewallPolicy = FirewallPolicy.DNAT_TO_HONEYPOT;
            
            honeypot_sccp_gt = SS7FirewallConfig.get("$.sigfw_configuration.firewall_rules.honeypot.sccp_gt");
            honeypot_dnat_session_expiration_timeout = Integer.parseInt((String)SS7FirewallConfig.get("$.sigfw_configuration.firewall_rules.honeypot.dnat_session_expiration_timeout"));
            
            
        } else if (firewall_policy.equals("ALLOW")) {
            firewallPolicy = FirewallPolicy.ALLOW;
        }
        //System.out.println("firewall_policy_enum = " + firewallPolicy.toString());    
        
        
        List<String> oc_blacklist = SS7FirewallConfig.get("$.sigfw_configuration.firewall_rules.tcap.oc_blacklist");
        tcap_oc_blacklist = new ConcurrentSkipListMap<String, String>();
        for (final String s : oc_blacklist) {
            tcap_oc_blacklist.put(s, ""); 
        }
        //System.out.println("tcap_oc_blacklist size = " + tcap_oc_blacklist.size());     
        
        List<String> imsi = SS7FirewallConfig.get("$.operator_configuration.Home_IMSI_prefixes");
        hplmn_imsi = new ConcurrentSkipListMap<String, String>();
        for (final String s : imsi) {
            hplmn_imsi.put(s, ""); 
        }
        
        List<String> gt = SS7FirewallConfig.get("$.operator_configuration.Home_GT_prefixes");
        hplmn_gt = new ConcurrentSkipListMap<String, String>();
        for (final String s : gt) {
            hplmn_gt.put(s + "*", ""); 
        }
        
        List<String> cat2_oc_blacklist = SS7FirewallConfig.get("$.sigfw_configuration.firewall_rules.map.cat2_oc_blacklist");
        map_cat2_oc_blacklist = new ConcurrentSkipListMap<String, String>();
        for (final String s : cat2_oc_blacklist) {
            map_cat2_oc_blacklist.put(s, ""); 
        }
        
        List<String> blacklist_rules = SS7FirewallConfig.get("$.sigfw_configuration.firewall_rules.lua.blacklist_rules");
        lua_blacklist_rules = new ConcurrentSkipListMap<Integer, String>();
        int k = 0;
        for (final String s : blacklist_rules) {
            lua_blacklist_rules.put(k, s);
            k++;
        }
        
        // ------------------------------------
        // Encryption
        called_gt_encryption = new ConcurrentSkipListMap<String, PublicKey>();
        try {
            List<Map<String, Object>> _called_gt_encryption = SS7FirewallConfig.get("$.sigfw_configuration.encryption_rules.called_gt_encryption");
            for (int i = 0; i < _called_gt_encryption.size(); i++) {
                String called_gt = (String)_called_gt_encryption.get(i).get("called_gt");
                if (called_gt != null) {
                    
                    PublicKey publicKey = null;
                    byte[] publicKeyBytes =  Base64.getDecoder().decode((String)_called_gt_encryption.get(i).get("public_key"));
                    String publicKeyType = (String)_called_gt_encryption.get(i).get("public_key_type");
                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                    
                    if (publicKeyType.equals("RSA")) {
                        publicKey = keyFactoryRSA.generatePublic(pubKeySpec);
                    } else if (publicKeyType.equals("EC")) {
                        publicKey = keyFactoryEC.generatePublic(pubKeySpec);
                    }
                    called_gt_encryption.put(called_gt, publicKey);
                }
            }
        } catch (InvalidKeySpecException ex) {
           Logger.getLogger(SS7FirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        called_gt_decryption = new ConcurrentSkipListMap<String, KeyPair>();
        try {
            List<Map<String, Object>> _called_gt_decryption = SS7FirewallConfig.get("$.sigfw_configuration.encryption_rules.called_gt_decryption");
            for (int i = 0; i < _called_gt_decryption.size(); i++) {
                String called_gt = (String)_called_gt_decryption.get(i).get("called_gt");
                if (called_gt != null) {
                    
                    PrivateKey privateKey = null;
                    byte[] privateKeyBytes =  Base64.getDecoder().decode((String)_called_gt_decryption.get(i).get("private_key"));
                    String privateKeyType = (String)_called_gt_decryption.get(i).get("private_key_type");
                    PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                    
                    if (privateKeyType.equals("RSA")) {
                        privateKey = keyFactoryRSA.generatePrivate(privKeySpec);
                    } else if (privateKeyType.equals("EC")) {
                        privateKey = keyFactoryEC.generatePrivate(privKeySpec);
                    }
                    
                    PublicKey publicKey = null;
                    byte[] publicKeyBytes =  Base64.getDecoder().decode((String)_called_gt_decryption.get(i).get("public_key"));
                    String publicKeyType = (String)_called_gt_decryption.get(i).get("public_key_type");
                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                    
                    if (publicKeyType.equals("RSA")) {
                        publicKey = keyFactoryRSA.generatePublic(pubKeySpec);
                    } else if (publicKeyType.equals("EC")) {
                        publicKey = keyFactoryEC.generatePublic(pubKeySpec);
                    }
                    
                    KeyPair keypair = new KeyPair(publicKey, privateKey);
                    called_gt_decryption.put(called_gt, keypair);
                }
            }
        } catch (InvalidKeySpecException ex) {
           Logger.getLogger(SS7FirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        encryption_autodiscovery = (String)SS7FirewallConfig.get("$.sigfw_configuration.encryption_rules.autodiscovery");
            
        // ------------------------------------
        // ------------------------------------
        // Signing
        calling_gt_verify = new ConcurrentSkipListMap<String, PublicKey>();
        try {
            List<Map<String, Object>> _calling_gt_verify = SS7FirewallConfig.get("$.sigfw_configuration.signature_rules.calling_gt_verify");
            for (int i = 0; i < _calling_gt_verify.size(); i++) {
                String calling_gt = (String)_calling_gt_verify.get(i).get("calling_gt");
                if (calling_gt != null) {
                    
                    PublicKey publicKey = null;
                    byte[] publicKeyBytes =  Base64.getDecoder().decode((String)_calling_gt_verify.get(i).get("public_key"));
                    String publicKeyType = (String)_calling_gt_verify.get(i).get("public_key_type");
                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                    
                    if (publicKeyType.equals("RSA")) {
                        publicKey = keyFactoryRSA.generatePublic(pubKeySpec);
                    } else if (publicKeyType.equals("EC")) {
                        publicKey = keyFactoryEC.generatePublic(pubKeySpec);
                    }
                    calling_gt_verify.put(calling_gt, publicKey);
                }
            }
        } catch (InvalidKeySpecException ex) {
           Logger.getLogger(SS7FirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        calling_gt_signing = new ConcurrentSkipListMap<String, KeyPair>();
        try {
            List<Map<String, Object>> _calling_gt_signing = SS7FirewallConfig.get("$.sigfw_configuration.signature_rules.calling_gt_signing");
            for (int i = 0; i < _calling_gt_signing.size(); i++) {
                String calling_gt = (String)_calling_gt_signing.get(i).get("calling_gt");
                if (calling_gt != null) {
                    
                    PrivateKey privateKey = null;
                    byte[] privateKeyBytes =  Base64.getDecoder().decode((String)_calling_gt_signing.get(i).get("private_key"));
                    String privateKeyType = (String)_calling_gt_signing.get(i).get("private_key_type");
                    PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                    
                    if (privateKeyType.equals("RSA")) {
                        privateKey = keyFactoryRSA.generatePrivate(privKeySpec);
                    } else if (privateKeyType.equals("EC")) {
                        privateKey = keyFactoryEC.generatePrivate(privKeySpec);
                    }
                    
                    PublicKey publicKey = null;
                    byte[] publicKeyBytes =  Base64.getDecoder().decode((String)_calling_gt_signing.get(i).get("public_key"));
                    String publicKeyType = (String)_calling_gt_signing.get(i).get("public_key_type");
                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                    
                    if (publicKeyType.equals("RSA")) {
                        publicKey = keyFactoryRSA.generatePublic(pubKeySpec);
                    } else if (publicKeyType.equals("EC")) {
                        publicKey = keyFactoryEC.generatePublic(pubKeySpec);
                    }
                    
                    KeyPair keypair = new KeyPair(publicKey, privateKey);
                    calling_gt_signing.put(calling_gt, keypair);
                }
            }
        } catch (InvalidKeySpecException ex) {
           Logger.getLogger(SS7FirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        // ------------------------------------
        
        try {
            mthreat_salt = (String)SS7FirewallConfig.get("$.sigfw_configuration.firewall_rules.mthreat.mthreat_salt");
        } catch (PathNotFoundException ex) {
            //Logger.getLogger(SS7FirewallConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        //String sctp_management_name = jsonConf.read("$.sigfw_configuration.sctp.sctp_management_name");
        //System.out.println("sctp_management_name = " + (String)SS7FirewallConfig.get("$.sigfw_configuration.sctp.sctp_management_name"));
        
        //List<Map<String, Object>> sctp_server = SS7FirewallConfig.get("$.sigfw_configuration.sctp.sctp_server");
        //System.out.println("server_name = " + sctp_server.get(0).get("server_name"));
        
        //List<String> remote_pc = SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_server.remote_pc");
        //System.out.println("remote_pc[0] = " + remote_pc.get(0));
        
        /*JSONParser parser = new JSONParser();
 
        try {
 
            Object obj = parser.parse(new FileReader(filename));
 
            JSONObject jsonObject = (JSONObject) obj;
            
            jsonConf = (JSONObject) jsonObject.get("sigfw_configuration");
            
            //
            //JSONArray companyList = (JSONArray) sigfw_configuration.get("dns_server_list");
            //Iterator<String> iterator = companyList.iterator();
            //while (iterator.hasNext()) {
            //    System.out.println("DNS: " + iterator.next());
            //}
            
            //String name = (String) jsonObject.get("Name");
            //String author = (String) jsonObject.get("Author");
            //JSONArray companyList = (JSONArray) jsonObject.get("Company List");
 
            //System.out.println("Name: " + name);
            //System.out.println("Author: " + author);
            //System.out.println("\nCompany List:");
            //Iterator<String> iterator = companyList.iterator();
            //while (iterator.hasNext()) {
            //    System.out.println(iterator.next());
            //}
 
        } catch (Exception e) {
            e.printStackTrace();
        // ------------------------------------
        
        //String sctp_management_name = jsonConf.read("$.sigfw_configuration.sctp.sctp_management_name");
        //System.out.println("sctp_management_name = " + (String)SS7FirewallConfig.get("$.sigfw_configuration.sctp.sctp_management_name"));
        
        //List<Map<String, Object>> sctp_server = SS7FirewallConfig.get("$.sigfw_configuration.sctp.sctp_server");
        //System.out.println("server_name = " + sctp_server.get(0).get("server_name"));
        
        //List<String> remote_pc = SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_server.remote_pc");
        //System.out.println("remote_pc[0] = " + remote_pc.get(0));
        
        /*JSONParser parser = new JSONParser();
 
        try {
 
            Object obj = parser.parse(new FileReader(filename));
 
            JSONObject jsonObject = (JSONObject) obj;
            
            jsonConf = (JSONObject) jsonObject.get("sigfw_configuration");
            
            //
            //JSONArray companyList = (JSONArray) sigfw_configuration.get("dns_server_list");
            //Iterator<String> iterator = companyList.iterator();
            //while (iterator.hasNext()) {
            //    System.out.println("DNS: " + iterator.next());
            //}
            
            //String name = (String) jsonObject.get("Name");
            //String author = (String) jsonObject.get("Author");
            //JSONArray companyList = (JSONArray) jsonObject.get("Company List");
 
            //System.out.println("Name: " + name);
            //System.out.println("Author: " + author);
            //System.out.println("\nCompany List:");
            //Iterator<String> iterator = companyList.iterator();
            //while (iterator.hasNext()) {
            //    System.out.println(iterator.next());
            //}
 
        } catch (Exception e) {
            e.printStackTrace();
        }*/
    }
    
    /**
     * Save configuration to json
     * @param filename
     * @throws java.io.FileNotFoundException
     */
    public static void saveConfigToFile(String filename) throws FileNotFoundException {
        
        JSONObject j = (JSONObject) jsonConfObject.get("sigfw_configuration");
        j = (JSONObject) j.get("firewall_rules");
        
        JSONObject sccp = (JSONObject) j.get("sccp");
        JSONArray calling_gt_blacklist = (JSONArray) sccp.get("calling_gt_blacklist");
        calling_gt_blacklist.clear();
        for (String key : sccp_calling_gt_blacklist.keySet()) {
            calling_gt_blacklist.add(key);
        }
        
        JSONObject tcap = (JSONObject) j.get("tcap");
        JSONArray oc_blacklist = (JSONArray) tcap.get("oc_blacklist");
        oc_blacklist.clear();
        for (String key : tcap_oc_blacklist.keySet()) {
            oc_blacklist.add(key);
        }
        
        JSONObject map = (JSONObject) j.get("map");
        JSONArray cat2_oc_blacklist = (JSONArray) map.get("cat2_oc_blacklist");
        cat2_oc_blacklist.clear();
        for (String key : map_cat2_oc_blacklist.keySet()) {
            cat2_oc_blacklist.add(key);
        }
        
        j = (JSONObject) jsonConfObject.get("sigfw_configuration");
        j = (JSONObject) j.get("encryption_rules");
        JSONArray j_called_gt_encryption = (JSONArray) j.get("called_gt_encryption");
        j_called_gt_encryption.clear();
        for (String key : called_gt_encryption.keySet()) {
            JSONObject c = new JSONObject();
            c.put("calling_gt", key);
            c.put("public_key", Base64.getEncoder().encodeToString(called_gt_encryption.get(key).getEncoded()));
            j_called_gt_encryption.add(c);
        }
        
        // TODO more runtime variables to save to config
        
        try {         
            FileWriter file = new FileWriter(filename);
            //file.write(jsonConfObject.toJSONString());
            
            Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
            String jsonOutput = gson.toJson(jsonConfObject);
            file.write(jsonOutput);

            file.flush();
            file.close();
 
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
}
