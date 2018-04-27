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
 * ExtensionLoader is using the work by Scott Robinson, Sep 2013
 * http://stackabuse.com/example-loading-a-java-class-at-runtime/
 *
 * Modified jSS7 SctpClient.java example
 */
package sigfw.tests;

import sigfw.common.ExternalFirewallRules;
import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import com.p1sec.sigfw.SigFW_interface.FirewallRulesInterface;

public class ExtensionLoaderTest {

    public static void main(String[] args) throws Exception {
        
        try {
            // Constructing a URL form the path to JAR
            URL u = new URL("file://" + System.getProperty("user.dir")  + "/src/main/resources/SigFW_extension-1.0.jar");
            System.out.println("file://" + System.getProperty("user.dir")  + "/src/main/resources/SigFW_extension-1.0.jar");

            // Creating an instance of URLClassloader using the above URL and parent classloader 
            ClassLoader loader  = URLClassLoader.newInstance(new URL[]{u}, ExternalFirewallRules.class.getClassLoader());

            // Returns the class object
            Class<?> yourMainClass = Class.forName("com.p1sec.sigfw.SigFW_extension.rules.ExtendedExternalFirewallRules", true, loader);

            FirewallRulesInterface object1 = (FirewallRulesInterface) yourMainClass.getDeclaredConstructor().newInstance();
            System.out.println(object1.ss7FirewallRules(null));
        } catch (Exception e) {
            System.out.println(e.toString());
            
            FirewallRulesInterface object1 = (FirewallRulesInterface)new ExternalFirewallRules();
            System.out.println(object1.ss7FirewallRules(null));
        }
        
    }
}
