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

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.jdiameter.api.Avp;
import org.jdiameter.api.AvpDataException;
import org.jdiameter.api.AvpSet;

/**
 *
 * @author Martin Kacer
 */
public class Utils {
    
    protected static final Logger logger = Logger.getLogger(Crypto.class);
    static {
        configLog4j();
    }
    
    protected static void configLog4j() {
       InputStream inStreamLog4j = Utils.class.getClassLoader().getResourceAsStream("log4j.properties");
       Properties propertiesLog4j = new Properties();
       try {
           propertiesLog4j.load(inStreamLog4j);
           PropertyConfigurator.configure(propertiesLog4j);
       } catch (Exception e) {
           e.printStackTrace();
       }

       logger.debug("log4j configured");
    }
    
    /**
     * Method to split byte array 
     * 
     * @param bytes original byte array
     * @param chunkSize chunk size
     * @return two dimensional byte array
     */
    public static byte[][] splitByteArray(byte[] bytes, int chunkSize) {
        int len = bytes.length;
        int counter = 0;

        int size = ((bytes.length - 1) / chunkSize) + 1;
        byte[][] newArray = new byte[size][]; 

        for (int i = 0; i < len - chunkSize + 1; i += chunkSize) {
            newArray[counter++] = Arrays.copyOfRange(bytes, i, i + chunkSize);
        }

        if (len % chunkSize != 0) {
            newArray[counter] = Arrays.copyOfRange(bytes, len - len % chunkSize, len);
        }
        
        return newArray;
    }
    
    /**
     * Concatenate two byte arrays
     * 
     * @param bytes first byte array
     * @param chunkSize second byte array
     * @return concatenated byte array
     */
    public static byte[] concatByteArray(byte[] a, byte[] b) {
        if (a == null) { 
            return b;
        }
        if (b == null) {
            return a;
        }
        
        byte[] r = new byte[a.length + b.length];

        System.arraycopy(a, 0, r, 0, a.length);

        System.arraycopy(b, 0, r, a.length, b.length);
        
        return r;
    }
    
     // workaround because in jDiameter AvpImpl, AvpSetImpl is not public
    // TODO submit to jDiameter to make AvpImpl, AvpSetImpl public
    private static final int INT32_SIZE = 4;
    
    public static byte[] int32ToBytes(int value) {
        byte[] bytes = new byte[INT32_SIZE];
        bytes[0] = (byte) (value >> 24 & 0xFF);
        bytes[1] = (byte) (value >> 16 & 0xFF);
        bytes[2] = (byte) (value >> 8 & 0xFF);
        bytes[3] = (byte) (value >> 0 & 0xFF);
        return bytes;
    }
    
    public static byte[] encodeAvp(Avp avp) {
        try {
            int payloadSize = avp.getRaw().length;
            boolean hasVendorId = avp.getVendorId() != 0;
            int origLength = payloadSize + 8 + (hasVendorId ? 4 : 0);
            int tmp = payloadSize % 4;
            int paddingSize = tmp > 0 ? (4 - tmp) : 0;

            byte[] bCode = Utils.int32ToBytes(avp.getCode());
            int flags = (byte) ((hasVendorId ? 0x80 : 0)
                    | (avp.isMandatory() ? 0x40 : 0) | (avp.isEncrypted() ? 0x20 : 0));
            byte[] bFlags = Utils.int32ToBytes(((flags << 24) & 0xFF000000) + origLength);
            byte[] bVendor = hasVendorId ? Utils.int32ToBytes((int) avp.getVendorId()) : new byte[0];
            return concat(origLength + paddingSize, bCode, bFlags, bVendor, avp.getRaw());
        } catch (Exception e) {
            logger.debug("Error during encode avp", e);
            return new byte[0];
        }
    }
    
    public static byte[] concat(int length, byte[]... arrays) {
        if (length == 0) {
            for (byte[] array : arrays) {
                length += array.length;
            }
        }
        byte[] result = new byte[length];
        int pos = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, pos, array.length);
            pos += array.length;
        }
        return result;
    }
    
       protected static class DynamicByteArray {

        private byte[] array;
        private int size;

        public DynamicByteArray(int cap) {
          array = new byte[cap > 0 ? cap : 256];
          size = 0;
        }

        public int get(int pos) {
          if (pos >= size) {
            throw new ArrayIndexOutOfBoundsException();
          }
          return array[pos];
        }

        public void add(byte[] bytes) {
          if (size + bytes.length > array.length) {
            byte[] newarray = new byte[array.length + bytes.length * 2];
            System.arraycopy(array, 0, newarray, 0, size);
            array = newarray;
          }
          System.arraycopy(bytes, 0, array, size, bytes.length);
          size += bytes.length;
        }

        public byte[] getResult() {
          return Arrays.copyOfRange(array, 0, size);
        }
    }
    
    public static byte[] encodeAvpSet(AvpSet avps) {
        //ByteArrayOutputStream out = new ByteArrayOutputStream();
        DynamicByteArray dba = new DynamicByteArray(0);
        try {
          //DataOutputStream data = new DataOutputStream(out);
          for (Avp a : avps) {
            /*if (a instanceof AvpImpl) {
              AvpImpl aImpl = (AvpImpl) a;
              if (aImpl.rawData.length == 0 && aImpl.groupedData != null) {
                aImpl.rawData = encodeAvpSet(a.getGrouped());
              }
              //data.write(newEncodeAvp(aImpl));
              dba.add(encodeAvp(aImpl));
            }*/
            
            // workaround because of AvpImpl is not public
            boolean hasVendorId = a.getVendorId() != 0;
            int flags = (byte) ((hasVendorId ? 0x80 : 0)
                    | (a.isMandatory() ? 0x40 : 0) | (a.isEncrypted() ? 0x20 : 0));
            AvpImpl aImpl = new AvpImpl(a.getCode(), flags, a.getVendorId(), a.getRawData());
            if (aImpl.rawData.length == 0 && aImpl.groupedData != null) {
              aImpl.rawData = encodeAvpSet(a.getGrouped());
            }
            dba.add(Utils.encodeAvp(aImpl));
          }
        }
        catch (Exception e) {
          e.printStackTrace();
          logger.debug("Error during encode avps", e);
        }
        return dba.getResult();
    }
    
    public static Avp decodeAvp(byte[] in_b ) throws IOException, AvpDataException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(in_b));
        int code = in.readInt();
        int tmp = in.readInt();
        int counter = 0;
        
        int flags = (tmp >> 24) & 0xFF;
        int length = tmp & 0xFFFFFF;
        if (length < 0 || counter + length > in_b.length) {
            throw new AvpDataException("Not enough data in buffer!");
        }
        long vendor = 0;
        boolean hasVendor = false;
        if ((flags & 0x80) != 0) {
            vendor = in.readInt();
            hasVendor = true;
        }
        // Determine body L = length - 4(code) -1(flags) -3(length) [-4(vendor)]
        byte[] rawData = new byte[length - (8 + (hasVendor ? 4 : 0))];
        in.read(rawData);
        // skip remaining.
        // TODO: Do we need to padd everything? Or on send stack should properly fill byte[] ... ?
        if (length % 4 != 0) {
            for (int i; length % 4 != 0; length += i) {
                i = (int) in.skip((4 - length % 4));
            }
        }
        AvpImpl avp = new AvpImpl(code, (short) flags, (int) vendor, rawData);
        return avp;
    }
    
    public static AvpSetImpl decodeAvpSet(byte[] buffer, int shift) throws IOException, AvpDataException {
        AvpSetImpl avps = new AvpSetImpl();
        int tmp, counter = shift;
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(buffer, shift, buffer.length /* - shift ? */));

        while (counter < buffer.length) {
          int code = in.readInt();
          tmp = in.readInt();
          int flags = (tmp >> 24) & 0xFF;
          int length  = tmp & 0xFFFFFF;
          if (length < 0 || counter + length > buffer.length) {
            throw new AvpDataException("Not enough data in buffer!");
          }
          long vendor = 0;
          boolean hasVendor = false;
          if ((flags & 0x80) != 0) {
            vendor = in.readInt();
            hasVendor = true;
          }
          // Determine body L = length - 4(code) -1(flags) -3(length) [-4(vendor)]
          byte[] rawData = new byte[length - (8 + (hasVendor ? 4 : 0))];
          in.read(rawData);
          // skip remaining.
          // TODO: Do we need to padd everything? Or on send stack should properly fill byte[] ... ?
          if (length % 4 != 0) {
            for (int i; length % 4 != 0; length += i) {
              i = (int) in.skip((4 - length % 4));
            }
          }
          AvpImpl avp = new AvpImpl(code, (short) flags, (int) vendor, rawData);
          avps.addAvp(avp);
          counter += length;
        }
        return avps;
    }
}
