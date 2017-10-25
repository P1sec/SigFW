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
package sigfw.connectorMThreat;

import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Martin Kacer
 */
public class ConnectorMThreat implements ConnectorMThreatModuleInterface, Runnable{
    private static org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(ConnectorMThreat.class);
    final static int THREADS_NUMBER = 1;
    final static int THREADS_SLEEP_TIME = 3000;     // in ms
    final static int MAX_ALERTS_IN_QUEUE = 10000;
    ExecutorService executor = Executors.newFixedThreadPool(THREADS_NUMBER);
    boolean isRunning = false;
    
    protected ConnectorMThreatModuleInterface module = null;
    protected static ConcurrentLinkedDeque<String> mThreat_alerts;
    
    public boolean initialize(Class<?> cls, ConcurrentLinkedDeque<String> alerts) {
        mThreat_alerts = alerts;
        if (cls == ConnectorMThreatModuleRest.class) {
            module = new ConnectorMThreatModuleRest();
            
            for (int i = 0; i < THREADS_NUMBER; i++) {
                executor.execute(this);
            }
            isRunning = true;
            return true;
        }
        return false;
    }

    public boolean addServer(String url, String username, String password) {
        if (module == null) {
            return false;
        }
        return module.addServer(url, username, password);
    }

    public boolean removeServer(String url) {
        if (module == null) {
            return false;
        }
        return module.removeServer(url);
    }

    public boolean sendAlert(String alert) {
        if (module == null) {
            return false;
        }
        return module.sendAlert(alert);
    }

    public void run() {
        synchronized(this) {
            while (isRunning) {
                try {
                    if (mThreat_alerts.size() > 0) {
                        // send alerts
                        if(module.sendAlert(mThreat_alerts.getFirst())) {
                            mThreat_alerts.poll();
                        } else {
                            this.wait(THREADS_SLEEP_TIME);
                        }
                    } else {
                        // remove too much alerts from queue
                        while (mThreat_alerts.size() > MAX_ALERTS_IN_QUEUE) {
                             mThreat_alerts.poll();
                        }
                        
                        this.wait(THREADS_SLEEP_TIME);
                    }
                } catch (InterruptedException ex) {
                    Logger.getLogger(ConnectorMThreat.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }
    
}
