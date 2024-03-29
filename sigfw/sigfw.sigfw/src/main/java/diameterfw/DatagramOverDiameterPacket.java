/**
 * SigFW
 * Open Source SS7/Diameter firewall
 * By Martin Kacer, Philippe Langlois
 * Copyright 2021, P1 Security S.A.S and individual contributors
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

import java.net.DatagramPacket;

/**
 *
 * @author Martin Kacer
 */
public class DatagramOverDiameterPacket {
    private String peer_realm;
    private DatagramPacket p;

    public DatagramOverDiameterPacket(String peer_realm, DatagramPacket p) {
        this.peer_realm = peer_realm;
        this.p = p;
    }

    public String getPeer_realm() {
        return peer_realm;
    }

    public DatagramPacket getP() {
        return p;
    }

    public void setPeer_realm(String peer_realm) {
        this.peer_realm = peer_realm;
    }

    public void setP(DatagramPacket p) {
        this.p = p;
    } 
}
