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

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Class used for testing encryption.
 * 
 * @author Martin Kacer
 */
public class EncryptionTest {
    public static void main(String[] args) throws Exception {

        
        // Genererate Keys
        KeyGenerator keyGenerator = KeyGenerator.getInstance("Blowfish");
        keyGenerator.init(128);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        System.out.println("Private Key Format = " + new String(keyPair.getPrivate().getFormat()));
        System.out.println("Private Key = " + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        System.out.println("Public Key Format = " + new String(keyPair.getPublic().getFormat()));
        System.out.println("Public Key = " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        
       

        /*
        // Load Keys from Base64
        Private Key Format = PKCS#8
        Private Key = MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANTNa+aaWN0o2bq7Y6YJAZbqMNC11P9i2tDH7pxUS8dDDVI0DKg8PFJEFGJ4Al3kkXMvCQKNTZGfvkwZHLINWgIlxkabtwPBVHo7+kQ+q44ygmNyhK8tFihMSP+U4saHZR7GZL2wWjFyMHL+NhPY83RDJ8JGuBvg0KKYFAWF2UaPAgMBAAECgYEApWU33RbPxKzwdUMaEz1iv+IrqLv63bf+rFEIsvaNo0UJQH/16nhOxf3l/haaeFGjfuvqy9H5nRqUdF78P6NC9YeGP+5VqF78UQaWIYRLLEuss4vHopLJc2Zd5Gqs8Wm2EhuRKUNeI3N3ru4Exns5GRp6jnQXZ8hT4OPDb65sgpkCQQDp/dlKcJC1rz+sPIdiCEj2Bb9WunRK9y7j3Scly46dZwTR5AZHKjzFS1uL32QZ8JEZgzuYyyRSjxIfsecFk/xbAkEA6NFe5T4IWq7X1G7oRIhzIf7t4ARbWRJnW8zLZi7icRQ9s1Tpi7e6pjcD8q3pfN0U3r/qyQ5DgIwhm4mHhCUE3QJBAODuE636LTFpiISyHtY+7pwJBFiDnfzeRmXmlpY/ahWnDTwSvXI1iPuDKDp6AMjqtyDWRTjotj7ip2JuaoyzKBcCQQDlT8Mt++lymB/RBuQTDGqKI3PcX64xjyTqkE4OeUNjqVIUXiAiE3bt2+YxkwYUjBTQSStRmJD3/g3kCpPFnkipAkAHZ0s1GJCuq8qLabde3OkUl4EVRK+BZWnifpy3B8ctAS/eu/Lw9l1n6iu8bsNJVNePlIBB97RB983jxyPfQeyP
        Public Key Format = X.509
        Public Key = MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUzWvmmljdKNm6u2OmCQGW6jDQtdT/YtrQx+6cVEvHQw1SNAyoPDxSRBRieAJd5JFzLwkCjU2Rn75MGRyyDVoCJcZGm7cDwVR6O/pEPquOMoJjcoSvLRYoTEj/lOLGh2UexmS9sFoxcjBy/jYT2PN0QyfCRrgb4NCimBQFhdlGjwIDAQAB
        */
    /*    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        
        byte[] publicKeyBytes =  Base64.getDecoder().decode("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUzWvmmljdKNm6u2OmCQGW6jDQtdT/YtrQx+6cVEvHQw1SNAyoPDxSRBRieAJd5JFzLwkCjU2Rn75MGRyyDVoCJcZGm7cDwVR6O/pEPquOMoJjcoSvLRYoTEj/lOLGh2UexmS9sFoxcjBy/jYT2PN0QyfCRrgb4NCimBQFhdlGjwIDAQAB");
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
        
        byte[] privateKeyBytes = Base64.getDecoder().decode("MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANTNa+aaWN0o2bq7Y6YJAZbqMNC11P9i2tDH7pxUS8dDDVI0DKg8PFJEFGJ4Al3kkXMvCQKNTZGfvkwZHLINWgIlxkabtwPBVHo7+kQ+q44ygmNyhK8tFihMSP+U4saHZR7GZL2wWjFyMHL+NhPY83RDJ8JGuBvg0KKYFAWF2UaPAgMBAAECgYEApWU33RbPxKzwdUMaEz1iv+IrqLv63bf+rFEIsvaNo0UJQH/16nhOxf3l/haaeFGjfuvqy9H5nRqUdF78P6NC9YeGP+5VqF78UQaWIYRLLEuss4vHopLJc2Zd5Gqs8Wm2EhuRKUNeI3N3ru4Exns5GRp6jnQXZ8hT4OPDb65sgpkCQQDp/dlKcJC1rz+sPIdiCEj2Bb9WunRK9y7j3Scly46dZwTR5AZHKjzFS1uL32QZ8JEZgzuYyyRSjxIfsecFk/xbAkEA6NFe5T4IWq7X1G7oRIhzIf7t4ARbWRJnW8zLZi7icRQ9s1Tpi7e6pjcD8q3pfN0U3r/qyQ5DgIwhm4mHhCUE3QJBAODuE636LTFpiISyHtY+7pwJBFiDnfzeRmXmlpY/ahWnDTwSvXI1iPuDKDp6AMjqtyDWRTjotj7ip2JuaoyzKBcCQQDlT8Mt++lymB/RBuQTDGqKI3PcX64xjyTqkE4OeUNjqVIUXiAiE3bt2+YxkwYUjBTQSStRmJD3/g3kCpPFnkipAkAHZ0s1GJCuq8qLabde3OkUl4EVRK+BZWnifpy3B8ctAS/eu/Lw9l1n6iu8bsNJVNePlIBB97RB983jxyPfQeyP");
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privKeySpec);
        
        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        
        System.out.println("Private Key Format = " + new String(keyPair.getPrivate().getFormat()));
        System.out.println("Private Key = " + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        System.out.println("Public Key Format = " + new String(keyPair.getPublic().getFormat()));
        System.out.println("Public Key = " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
     */   

        // Init
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        char[] pText = new char[255];
        Arrays.fill(pText, 'A');
        byte[] plainText = new String(pText).getBytes();
        System.out.println("Plain = " + new String(plainText));
        
        // Encode
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] cipherText = cipher.doFinal(plainText);
        //byte[] cipherText = Base64.getDecoder().decode("JnyTc+dK18IwjGCaQlFyhwqY5VDK+osXBt9i8nDNPGZAH/yEKyijTBZKlqRtYqFdCM/izCIh2UzfQj+gPpIOC6XwST7hOqTmkc2NY9yyzfp/69GSLJ8yh74TdE2os1plK4NiU3yK8kqo48vFeXuyfpQU+xkyln7JnOU7iSGDwAM=");
        //byte[] cipherText = Base64.getDecoder().decode("B6zehJfpUN8oiAj40hwckbU4B8/nafVHpuhFV0K6D6Xu43seMyNl6/DEqNLaBw5/Ek95li5OtbOxqs6fWMkOjcNki9dhOtgJoPloAINC7WhB6gLLuLcHQ0Gb7B5LjaRqdFQGZcNGdJd8BtaKHqM/o7jrJDNZrFBAV/TSAy3v1FE=");
        
        System.out.println("Encrypted Base64 = " + Base64.getEncoder().encodeToString(cipherText));
        
        // Decode
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedText = cipher.doFinal(cipherText);
        System.out.println("Decrypted = " + new String(decryptedText));

    }
}
