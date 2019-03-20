/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
