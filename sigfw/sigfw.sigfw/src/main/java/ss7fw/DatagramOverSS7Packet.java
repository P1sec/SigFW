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
package ss7fw;

import diameterfw.*;
import java.net.DatagramPacket;

/**
 *
 * @author Martin Kacer
 */
public class DatagramOverSS7Packet {
    private String peer_gt;
    private DatagramPacket p;

    public DatagramOverSS7Packet(String peer_gt, DatagramPacket p) {
        this.peer_gt = peer_gt;
        this.p = p;
    }

    public String getPeer_gt() {
        return peer_gt;
    }

    public DatagramPacket getP() {
        return p;
    }

    public void setPeer_gt(String peer_gt) {
        this.peer_gt = peer_gt;
    }

    public void setP(DatagramPacket p) {
        this.p = p;
    } 
}
