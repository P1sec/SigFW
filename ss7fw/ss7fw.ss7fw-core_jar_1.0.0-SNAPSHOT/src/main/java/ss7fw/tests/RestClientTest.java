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
package ss7fw.tests;


import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;


/**
 * Class to perform REST API tests.
 * 
 * @author Martin Kacer
 */
public class RestClientTest {
    
    public static Client configureClient() {
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

        //ClientConfig config = new ClientConfig();
        /*try {
            config.getProperties().put(HTTPSProperties.PROPERTY_HTTPS_PROPERTIES, new HTTPSProperties(
                    new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            },
                    ctx
            ));
        } catch (Exception e) {
        }*/
        
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

    public static Client createClient() {
        return configureClient();
    }
       
    public static void main(String[] args) throws Exception {
    
        try {
            //Client client = Client.create();
            // Accept self-signed certificates
            Client client = createClient();

            String username = "user";
            String password = "password";
            //client.addFilter(new HTTPBasicAuthFilter(username, password));
            HttpAuthenticationFeature feature = HttpAuthenticationFeature.basic(username, password);
            client.register(feature);
            
            WebTarget webResource = client.target("https://localhost:8443");
            WebTarget webResourceWithPath = webResource.path("ss7fw_api/1.0/eval_sccp_message_in_ids");
            WebTarget webResourceWithQueryParam = webResourceWithPath.matrixParam("sccp_raw", "12345");
            
            System.out.println(webResourceWithQueryParam);
            
            //ClientResponse response = webResourceWithQueryParam.accept("text/plain").get(ClientResponse.class);
            Response response = webResourceWithQueryParam.request("text/plain").get();
            
            if (response.getStatus() != 200) {
               throw new RuntimeException("Failed : HTTP error code : " + response.getStatus());
            }

            String output = response.readEntity(String.class);

            System.out.println("Output from Server .... \n");
            System.out.println(output);

	  } catch (Exception e) {
              e.printStackTrace();
	  }
        
    }
    
}



/*
import com.emc.rest.smart.Host;
import com.emc.rest.smart.SmartClientFactory;
import com.emc.rest.smart.SmartConfig;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.client.urlconnection.HTTPSProperties;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.glassfish.jersey.server.model.Parameter;

public class RestClientTest {
     
    public static void main(String[] args) throws Exception {
        
        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setKeyStorePath("ss7fw_keystore");
       
        //for localhost testing only
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
            new javax.net.ssl.HostnameVerifier(){

                public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession) {
                    //if (hostname.equals("localhost")) {
                        return true;
                    //}
                    //return false;
                }
            }
        );

        
        
        System.setProperty("javax.net.ssl.trustStore", "ss7fw_keystore");
        
        List<Host> initialHosts = new ArrayList<Host>();
        initialHosts.add(new Host(new URI("https://127.0.0.1:8443").getHost()));
        
        SmartConfig smartConfig = new SmartConfig(initialHosts);
        
       
        
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

        try {
            smartConfig.getProperties().put(HTTPSProperties.PROPERTY_HTTPS_PROPERTIES, new HTTPSProperties(
                    new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            },
                    ctx
            ));
        } catch (Exception e) {
        }
        
        smartConfig.getClasses().add(SizeOverrideWriter.InputStream.class);
        

        //for (String propName : smartConfig.getProperties().keySet()) {
        //   clientConfig.getProperties().put(propName, smartConfig.getProperty(propName));
        //}
        
        
        
        final Client client = SmartClientFactory.createSmartClient(smartConfig);
        
        System.out.println(client.getProperties());
        
        
        String path = "/rest/service";
        
        WebResource.Builder request = client.resource("https://127.0.0.1:8443").path(path).getRequestBuilder();

        ClientResponse response = request.get(ClientResponse.class);

        if (response.getStatus() > 299) throw new RuntimeException("error response: " + response.getStatus());

        String responseStr = response.getEntity(String.class);
        if (!responseStr.contains("Atmos")) throw new RuntimeException("unrecognized response string: " + responseStr);
    }
}*/
