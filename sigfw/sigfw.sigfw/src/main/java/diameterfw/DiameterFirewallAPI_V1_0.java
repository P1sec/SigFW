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
import java.util.SortedMap;
import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.GET;
import javax.ws.rs.MatrixParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

/**
 *
 * @author Martin Kacer
 */
@Path("diameterfw_api/1.0")
public class DiameterFirewallAPI_V1_0 {

    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("diameter_origin_realm_blacklist_add")
    public String diameter_origin_realm_blacklist_add(@MatrixParam("realm") String realm) {
        DiameterFirewallConfig.diameter_origin_realm_blacklist.put(realm, "");
        return "Successful";
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("diameter_origin_realm_blacklist_remove")
    public String diameter_origin_realm_blacklist_remove(@MatrixParam("realm") String realm) {
        DiameterFirewallConfig.diameter_origin_realm_blacklist.remove(realm);
        return "Successful";
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("diameter_origin_realm_blacklist_list")
    public String diameter_origin_realm_blacklist_list() {
        String s = "";
        for (SortedMap.Entry<String, String> entry : DiameterFirewallConfig.diameter_origin_realm_blacklist.entrySet()) {
            s += entry.getKey() + "\n";
        }
        return s;
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("diameter_application_id_whitelist_add")
    public String diameter_application_id_whitelist_add(@MatrixParam("ai") int ai) {
        DiameterFirewallConfig.diameter_application_id_whitelist.put((new Integer(ai)).toString(), "");
        return "Successful";
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("diameter_application_id_whitelist_remove")
    public String diameter_application_id_whitelist_remove(@MatrixParam("ai") int ai) {
        DiameterFirewallConfig.diameter_application_id_whitelist.remove((new Integer(ai)).toString());
        return "Successful";
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("diameter_application_id_whitelist_list")
    public String diameter_application_id_whitelist_list() {
        String s = "";
        for (SortedMap.Entry<String, String> entry : DiameterFirewallConfig.diameter_application_id_whitelist.entrySet()) {
            s += entry.getKey() + "\n";
        }
        return s;
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("diameter_command_code_blacklist_add")
    public String diameter_command_code_blacklist_add(@MatrixParam("cc") int cc) {
        DiameterFirewallConfig.diameter_command_code_blacklist.put((new Integer(cc)).toString(), "");
        return "Successful";
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("diameter_command_code_blacklist_remove")
    public String diameter_command_code_blacklist_remove(@MatrixParam("cc") int cc) {
        DiameterFirewallConfig.diameter_command_code_blacklist.remove((new Integer(cc)).toString());
        return "Successful";
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("diameter_command_code_blacklist_list")
    public String diameter_command_code_blacklist_list() {
        String s = "";
        for (SortedMap.Entry<String, String> entry : DiameterFirewallConfig.diameter_command_code_blacklist.entrySet()) {
            s += entry.getKey() + "\n";
        }
        return s;
    }
    
    /*@GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("get_diameter_trace")
    public String get_diameter_trace(@MatrixParam("n") int n) {
        String s = "";
        int i = n;
        while (i > 0 && DiameterFirewall.diameter_fifo.size() > 0 ) {
            s += DiameterFirewall.diameter_fifo.pop() + "\n";
            i--;
        }
        return s;
    }*/
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("get_status")
    public String get_status() {
        return DiameterFirewall.getStatus();
    }
    
    // IDS integration API - used only for test purposes on localhost simulating IDS backend
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("eval_diameter_message_in_ids")
    public String eval_diameter_message_in_ids(@MatrixParam("diameter_raw") String diameter_raw) {
        return "1";
    }
    
    // mThreat integration API - used only for test purposes on localhost simulating mThreat backend
    @POST
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("send_diameter_alert_to_mthreat")
    public Response send_diameter_alert_to_mthreat(String alert) {
        String output = alert;
        return Response.status(200).entity(output).build();
    }
}
