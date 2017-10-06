/**
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
 *
 */
package sigfw.connectorIDS;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;


/**
 * Connector to IDS module implementing REST.
 * 
 * @author Martin Kacer
 */
public class ConnectorIDSModuleRest implements ConnectorIDSModuleInterface {
    private static org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(ConnectorIDSModuleRest.class);
    List<Client> serverList = new ArrayList();
    List<WebTarget> serverTargetsList = new ArrayList();
    HashMap<Integer, Integer> serverBackoffAttempts = new HashMap<Integer, Integer>();
    private static final int SERVER_BACKOFFATTEMPTS = 1000;
    Random randomGenerator = new Random();
    
    /**
     * Create jersey client. 
     * Used to do not validate certificates or for other SSL/TLS options.
     * 
     */
    protected static Client createClient() {
        TrustManager[] certs = new TrustManager[]{
            new X509TrustManager() {
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType)
                        throws CertificateException {
                }

                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType)
                        throws CertificateException {
                }
            }
        };
        SSLContext ctx = null;
        try {
            ctx = SSLContext.getInstance("TLS");
            ctx.init(null, certs, new SecureRandom());
        } catch (java.security.GeneralSecurityException ex) {
        }
        HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
        
        Client client = ClientBuilder.newBuilder()
        .sslContext(ctx)
        .hostnameVerifier(
            new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            })
        .build();
        
        return client;
    }
    
    /**
     * Add IDS server
     * 
     * @param url url address of IDS server
     * @param username username for IDS server
     * @param password password for IDS server
     * @return true if successful
     */
    public boolean addServer(String url, String username, String password) {
        Client client = createClient();
        serverList.add(client);

        HttpAuthenticationFeature feature = HttpAuthenticationFeature.basic(username, password);
        client.register(feature);
        
        //WebTarget target = client.target(url).path("ss7fw_api/1.0/eval_sccp_message_in_ids");
        WebTarget target = client.target(url);
        serverTargetsList.add(target);
        
        return true;
    }

    /**
     * Remove IDS server
     * 
     * @param url url address of IDS server
     * @return true if successful
     */
    public boolean removeServer(String url) {
        for (int i = 0; i < serverTargetsList.size(); i++) {
            try {
                if (serverTargetsList.get(i).getUri().getHost().equals(new URI(url).getHost()) ) {
                    serverTargetsList.remove(i);
                    Client client = serverList.get(i);
                    if (client != null) {
                        client.close();
                    }
                    serverList.remove(i);
                    return true;
                }
            } catch (URISyntaxException ex) {
                Logger.getLogger(ConnectorIDSModuleRest.class.getName()).log(Level.SEVERE, null, ex);
                return false;
            }
        }
        return false;
    }

    /**
     * Evaluate SCCP message towards IDS server.
     * 
     * @param sccp_raw SCCP hex raw payload of message
     * @return true if message is valid and false if message should be filtered
     */
    public boolean evalSCCPMessage(String sccp_raw) {
        int attempts = serverList.size();
        
        Response response = null;
        String output = "1";
        
        int i = randomGenerator.nextInt(serverList.size());
        
        do {
            if (serverBackoffAttempts.get(i) == null || serverBackoffAttempts.get(i).intValue() <= 0) {
                try {
                    WebTarget webResourceWithQueryParam = serverTargetsList.get(i).matrixParam("sccp_raw", sccp_raw);
                    response = webResourceWithQueryParam.request("text/plain").get();
                    if (response.getStatus() == 200) {
                        output = response.readEntity(String.class);
                        logger.debug("evalSCCPMessage " + webResourceWithQueryParam + " Response: " + output);
                        break;
                    } else {
                        logger.warn("Connection failed for IDS API: HTTP error code : " + response.getStatus() + " for " + serverTargetsList.get(i));
                    }
                } catch (Exception e) {
                    serverBackoffAttempts.put(i, SERVER_BACKOFFATTEMPTS);
                    logger.warn("Connection failed for IDS API: " + serverTargetsList.get(i) + " " + e.toString());
                }
            } else {
                if (serverBackoffAttempts.get(i) != null) {
                    serverBackoffAttempts.put(i, serverBackoffAttempts.get(i).intValue() - 1);
                }
                i = randomGenerator.nextInt(serverList.size());
            }
            attempts--;
        } while (attempts > 0);

        
        return output.equals("1");
    }
    
    /**
     * Evaluate Diameter message towards IDS server.
     * 
     * @param diameter_raw Diameter hex raw payload of message
     * @return true if message is valid and false if message should be filtered
     */
    public boolean evalDiameterMessage(String diameter_raw) {
        int attempts = serverList.size();
        
        Response response = null;
        String output = "1";
        
        int i = randomGenerator.nextInt(serverList.size());
        
        do {
            if (serverBackoffAttempts.get(i) == null || serverBackoffAttempts.get(i).intValue() <= 0) {
                try {
                    WebTarget webResourceWithQueryParam = serverTargetsList.get(i).matrixParam("diameter_raw", diameter_raw);
                    response = webResourceWithQueryParam.request("text/plain").get();
                    if (response.getStatus() == 200) {
                        output = response.readEntity(String.class);
                        logger.debug("evalDiameterMessage " + webResourceWithQueryParam + " Response: " + output);
                        break;
                    } else {
                        logger.warn("Connection failed for IDS API: HTTP error code : " + response.getStatus() + " for " + serverTargetsList.get(i));
                    }
                } catch (Exception e) {
                    serverBackoffAttempts.put(i, SERVER_BACKOFFATTEMPTS);
                    logger.warn("Connection failed for IDS API: " + serverTargetsList.get(i) + " " + e.toString());
                }
            } else {
                if (serverBackoffAttempts.get(i) != null) {
                    serverBackoffAttempts.put(i, serverBackoffAttempts.get(i).intValue() - 1);
                }
                i = randomGenerator.nextInt(serverList.size());
            }
            attempts--;
        } while (attempts > 0);

        
        return output.equals("1");
    }
    
}
