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
package ss7fw;
import java.util.SortedMap;
import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.GET;
import javax.ws.rs.MatrixParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

/**
 * Firewall REST API implementation.
 * 
 * @author Martin Kacer
 */
@Path("ss7fw_api/1.0")
public class SS7FirewallAPI_V1_0 {

    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("sccp_calling_gt_blacklist_add")
    public String sccp_calling_gt_blacklist_add(@MatrixParam("gt") String gt) {
        SS7FirewallConfig.sccp_calling_gt_blacklist.put(gt, "");
        return "Successful";
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("sccp_calling_gt_blacklist_remove")
    public String sccp_calling_gt_blacklist_remove(@MatrixParam("gt") String gt) {
        SS7FirewallConfig.sccp_calling_gt_blacklist.remove(gt);
        return "Successful";
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("sccp_calling_gt_blacklist_list")
    public String sccp_calling_gt_blacklist_list() {
        String s = "";
        for (SortedMap.Entry<String, String> entry : SS7FirewallConfig.sccp_calling_gt_blacklist.entrySet()) {
            s += entry.getKey() + "\n";
        }
        return s;
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("tcap_oc_blacklist_add")
    public String tcap_oc_blacklist_add(@MatrixParam("oc") int oc) {
        SS7FirewallConfig.tcap_oc_blacklist.put((new Integer(oc)).toString(), "");
        return "Successful";
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("tcap_oc_blacklist_remove")
    public String tcap_oc_blacklist_remove(@MatrixParam("oc") int oc) {
        SS7FirewallConfig.tcap_oc_blacklist.remove((new Integer(oc)).toString());
        return "Successful";
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("tcap_oc_blacklist_list")
    public String tcap_oc_blacklist_list() {
        String s = "";
        for (SortedMap.Entry<String, String> entry : SS7FirewallConfig.tcap_oc_blacklist.entrySet()) {
            s += entry.getKey() + "\n";
        }
        return s;
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("map_cat2_oc_blacklist_add")
    public String map_cat2_oc_blacklist_add(@MatrixParam("oc") int oc) {
        SS7FirewallConfig.map_cat2_oc_blacklist.put((new Integer(oc)).toString(), "");
        return "Successful";
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("map_cat2_oc_blacklist_remove")
    public String map_cat2_oc_blacklist_remove(@MatrixParam("oc") int oc) {
        SS7FirewallConfig.map_cat2_oc_blacklist.remove((new Integer(oc)).toString());
        return "Successful";
    }
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("map_cat2_oc_blacklist_list")
    public String map_cat2_oc_blacklist_list() {
        String s = "";
        for (SortedMap.Entry<String, String> entry : SS7FirewallConfig.map_cat2_oc_blacklist.entrySet()) {
            s += entry.getKey() + "\n";
        }
        return s;
    }
    
    /*
    // M3UA FIFO
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("get_m3ua_trace")
    public String get_m3ua_trace(@MatrixParam("n") int n) {
        String s = "";
        int i = n;
        while (i > 0 && SS7Firewall.m3ua_fifo.size() > 0 ) {
            s += SS7Firewall.m3ua_fifo.pop() + "\n";
            i--;
        }
        return s;
    }*/
    
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("get_status")
    public String get_status() {
        return SS7Firewall.getStatus();
    }
    
    // IDS integration API - used only for test purposes on localhost simulating IDS backend
    @GET
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("eval_sccp_message_in_ids")
    public String eval_sccp_message_in_ids(@MatrixParam("sccp_raw") String sccp_raw) {
        return "1";
    }
    
    // mThreat integration API - used only for test purposes on localhost simulating mThreat backend
    @POST
    @Consumes("text/plain")
    @Produces("text/plain")
    @Path("send_ss7_alert_to_mthreat")
    public Response send_ss7_alert_to_mthreat(String alert) {
        String output = alert;
        return Response.status(200).entity(output).build();
    }
}
