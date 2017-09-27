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
package diameterfw;

import diameterfw.DiameterFirewall;
/**
 * First firewall instance used for testing encryption and signatures.
 * 
 * @author Martin Kacer
 *
 */
public class DiameterFirewallFirstInstance {
    public static void main(String[] args) throws Exception {
        String[] a = new String[1];
        a[0] = "sigfw_1.json";
        DiameterFirewall.main(a);
    }
}
