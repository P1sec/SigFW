// workaround because in jDiameter AvpImpl is not public
// TODO submit to jDiameter to make AvpImpl public

/*
  * TeleStax, Open Source Cloud Communications
  * Copyright 2011-2016, TeleStax Inc. and individual contributors
  * by the @authors tag.
  *
  * This program is free software: you can redistribute it and/or modify
  * under the terms of the GNU Affero General Public License as
  * published by the Free Software Foundation; either version 3 of
  * the License, or (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU Affero General Public License for more details.
  *
  * You should have received a copy of the GNU Affero General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>
  *
  * This file incorporates work covered by the following copyright and
  * permission notice:
  *
  *   JBoss, Home of Professional Open Source
  *   Copyright 2007-2011, Red Hat, Inc. and individual contributors
  *   by the @authors tag. See the copyright.txt in the distribution for a
  *   full listing of individual contributors.
  *
  *   This is free software; you can redistribute it and/or modify it
  *   under the terms of the GNU Lesser General Public License as
  *   published by the Free Software Foundation; either version 2.1 of
  *   the License, or (at your option) any later version.
  *
  *   This software is distributed in the hope that it will be useful,
  *   but WITHOUT ANY WARRANTY; without even the implied warranty of
  *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  *   Lesser General Public License for more details.
  *
  *   You should have received a copy of the GNU Lesser General Public
  *   License along with this software; if not, write to the Free
  *   Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
  *   02110-1301 USA, or see the FSF site: http://www.fsf.org.
  */

package sigfw.common;

import java.net.InetAddress;
import java.net.URISyntaxException;
import java.net.UnknownServiceException;
import java.util.Date;

import org.jdiameter.api.Avp;
import org.jdiameter.api.AvpDataException;
import org.jdiameter.api.AvpSet;
import org.jdiameter.api.InternalException;
import org.jdiameter.api.URI;
import org.jdiameter.client.impl.parser.ElementParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author erick.svenson@yahoo.com
 * @author <a href="mailto:brainslog@gmail.com"> Alexandre Mendonca </a>
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class AvpImpl implements Avp {

  private static final long serialVersionUID = 1L;
  private static final ElementParser parser = new ElementParser();
  int avpCode;
  public long vendorID;

  public boolean isMandatory = false;
  boolean isEncrypted = false;
  boolean isVendorSpecific = false;

  byte[] rawData = new byte[0];
  AvpSet groupedData;

  private static final Logger logger = LoggerFactory.getLogger(AvpImpl.class);

  public AvpImpl(int code, int flags, long vnd, byte[] data) {
    avpCode  = code;
    //
    isMandatory = (flags & 0x40) != 0;
    isEncrypted = (flags & 0x20) != 0;
    isVendorSpecific = (flags & 0x80) != 0;
    //
    vendorID = vnd;
    rawData  = data;
  }

  AvpImpl(Avp avp) {
    avpCode     = avp.getCode();
    vendorID    = avp.getVendorId();
    isMandatory = avp.isMandatory();
    isEncrypted = avp.isEncrypted();
    isVendorSpecific = avp.isVendorId();
    try {
      rawData = avp.getRaw();
      if (rawData == null || rawData.length == 0) {
        groupedData = avp.getGrouped();
      }
    }
    catch (AvpDataException e) {
      logger.debug("Can not create Avp", e);
    }
  }

  AvpImpl (int newCode, Avp avp) {
    this(avp);
    avpCode = newCode;
  }

  @Override
  public int getCode() {
    return avpCode;
  }

  @Override
  public boolean isVendorId() {
    return isVendorSpecific;
  }

  @Override
  public boolean isMandatory() {
    return isMandatory;
  }

  @Override
  public boolean isEncrypted() {
    return isEncrypted;
  }

  @Override
  public long getVendorId() {
    return vendorID;
  }

  @Override
  public byte[] getRaw() throws AvpDataException {
    return rawData;
  }

  @Override
  public byte[] getOctetString() throws AvpDataException {
    return rawData;
  }

  @Override
  public String getUTF8String() throws AvpDataException {
    try {
      return parser.bytesToUtf8String(rawData);
    }
    catch (Exception e) {
      throw new AvpDataException(e, this);
    }
  }

  @Override
  public int getInteger32() throws AvpDataException {
    try {
      return parser.bytesToInt(rawData);
    }
    catch (Exception e) {
      throw new AvpDataException(e, this);
    }
  }

  @Override
  public long getInteger64() throws AvpDataException {
    try {
      return parser.bytesToLong(rawData);
    }
    catch (Exception e) {
      throw new AvpDataException(e, this);
    }
  }

  @Override
  public long getUnsigned32() throws AvpDataException {
    try {
      byte[] u32ext = new byte[8];
      System.arraycopy(rawData, 0, u32ext, 4, 4);
      return parser.bytesToLong(u32ext);
    }
    catch (Exception e) {
      throw new AvpDataException(e, this);
    }
  }

  @Override
  public long getUnsigned64() throws AvpDataException {
    try {
      return parser.bytesToLong(rawData);
    }
    catch (Exception e) {
      throw new AvpDataException(e, this);
    }
  }

  @Override
  public float getFloat32() throws AvpDataException {
    try {
      return parser.bytesToFloat(rawData);
    }
    catch (Exception e) {
      throw new AvpDataException(e, this);
    }
  }

  @Override
  public double getFloat64() throws AvpDataException {
    try {
      return parser.bytesToDouble(rawData);
    }
    catch (Exception e) {
      throw new AvpDataException(e, this);
    }
  }

  @Override
  public InetAddress getAddress() throws AvpDataException {
    try {
      return parser.bytesToAddress(rawData);
    }
    catch (Exception e) {
      throw new AvpDataException(e, this);
    }
  }

  @Override
  public Date getTime() throws AvpDataException {
    try {
      return parser.bytesToDate(rawData);
    }
    catch (Exception e) {
      throw new AvpDataException(e, this);
    }
  }

  @Override
  public String getDiameterIdentity() throws AvpDataException {
    try {
      return parser.bytesToOctetString(rawData);
    }
    catch (Exception e) {
      throw new AvpDataException(e, this);
    }
  }

  @Override
  public URI getDiameterURI() throws AvpDataException {
    try {
      return new URI(parser.bytesToOctetString(rawData));
    }
    catch (URISyntaxException e) {
      throw new AvpDataException(e, this);
    }
    catch (UnknownServiceException e) {
      throw new AvpDataException(e, this);
    }
  }

  @Override
  public AvpSet getGrouped() throws AvpDataException {
    try {
      if (groupedData == null) {
        groupedData = parser.decodeAvpSet(rawData);
        rawData = new byte[0];
      }
      return groupedData;
    }
    catch (Exception e) {
      throw new AvpDataException(e, this);
    }
  }

  @Override
  public boolean isWrapperFor(Class<?> aClass) throws InternalException {
    return false;
  }

  @Override
  public <T> T unwrap(Class<T> aClass) throws InternalException {
    return null;
  }

  @Override
  public byte[] getRawData() {
    return (rawData == null || rawData.length == 0) ? parser.encodeAvpSet(groupedData) : rawData;
  }

  // Caching toString.. Avp shouldn't be modified once created.
  private String toString;

  @Override
  public String toString() {
    if (toString == null) {
      this.toString = new StringBuffer("AvpImpl [avpCode=").append(avpCode).append(", vendorID=").append(vendorID).append("]@").append(super.hashCode()).
          toString();
    }

    return this.toString;
  }
}
