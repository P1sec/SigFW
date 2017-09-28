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
package ss7fw.connectorIDS;

/**
 * Connector to IDS. The connector class should be protocol independent.
 * 
 * @author Martin Kacer
 */
public class ConnectorIDS implements ConnectorIDSModuleInterface{
    
    protected ConnectorIDSModuleInterface module = null;
    
    /**
     * Initialize Connector IDS.
     * 
     * @param cls connector module implementing some protocol
     * @return true if successful
     */
    public boolean initialize(Class<?> cls) {
        if (cls == ConnectorIDSModuleRest.class) {
            module = new ConnectorIDSModuleRest();
            return true;
        }
        return false;
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
        if (module == null) {
            return false;
        }
        return module.addServer(url, username, password);
    }

    /**
     * Remove IDS server
     * 
     * @param url url address of IDS server
     * @return true if successful
     */
    public boolean removeServer(String url) {
        if (module == null) {
            return false;
        }
        return module.removeServer(url);
    }

    /**
     * Evaluate SCCP message towards IDS server.
     * 
     * @param sccp_raw SCCP hex raw payload of message
     * @return true if message is valid and false if message should be filtered
     */
    public boolean evalSCCPMessage(String sccp_raw) {
        if (module == null) {
            return false;
        }
        return module.evalSCCPMessage(sccp_raw);
    }
    
}
