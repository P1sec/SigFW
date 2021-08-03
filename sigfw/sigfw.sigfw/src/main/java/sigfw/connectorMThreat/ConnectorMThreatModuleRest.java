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
package sigfw.connectorMThreat;

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
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;


/**
 *
 * @author Martin Kacer
 */
public class ConnectorMThreatModuleRest implements ConnectorMThreatModuleInterface {
    private static org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(ConnectorMThreatModuleRest.class);
    List<Client> serverList = new ArrayList();
    List<WebTarget> serverTargetsList = new ArrayList();
    HashMap<Integer, Integer> serverBackoffAttempts = new HashMap<Integer, Integer>();
    private static final int SERVER_BACKOFFATTEMPTS = 10;
    Random randomGenerator = new Random();
    
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
    
    public boolean addServer(String url, String username, String password) {
        Client client = createClient();
        serverList.add(client);

        HttpAuthenticationFeature feature = HttpAuthenticationFeature.basic(username, password);
        client.register(feature);
        
        WebTarget target = client.target(url);
        serverTargetsList.add(target);
        
        return true;
    }

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
                Logger.getLogger(ConnectorMThreatModuleRest.class.getName()).log(Level.SEVERE, null, ex);
                return false;
            }
        }
        return false;
    }

    public boolean sendAlert(String alert) {
        int attempts = serverList.size();
        
        Response response = null;
        String output = "";
        
        int i = randomGenerator.nextInt(serverList.size());
        
        do {
            if (serverBackoffAttempts.get(i) == null || serverBackoffAttempts.get(i).intValue() <= 0) {
                try {
                    //WebTarget webResourceWithQueryParam = serverTargetsList.get(i).matrixParam("sccp_raw", sccp_raw);
                    response = serverTargetsList.get(i).request("text/plain").post(Entity.entity(alert, MediaType.TEXT_PLAIN));
                    if (response.getStatus() == 200) {
                        output = response.readEntity(String.class);
                        logger.debug("sendAlert " + response.toString() + " Response: " + output);
                        break;
                    } else {
                        logger.warn("Connection failed for mThreat API: HTTP error code : " + response.getStatus() + " for " + serverTargetsList.get(i));
                        return false;
                    }
                } catch (Exception e) {
                    serverBackoffAttempts.put(i, SERVER_BACKOFFATTEMPTS);
                    logger.warn("Connection failed for mThreat API: " + serverTargetsList.get(i) + " " + e.toString());
                    return false;
                }
            } else {
                if (serverBackoffAttempts.get(i) != null) {
                    serverBackoffAttempts.put(i, serverBackoffAttempts.get(i).intValue() - 1);
                    return false;
                }
                i = randomGenerator.nextInt(serverList.size());
            }
            attempts--;
        } while (attempts > 0);

        
        return true;
    }
    
}
