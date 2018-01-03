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
package ss7fw;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import org.apache.log4j.Logger;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.Tag;
import org.mobicents.protocols.sctp.ManagementImpl;
import org.mobicents.protocols.ss7.m3ua.As;
import org.mobicents.protocols.ss7.m3ua.AspFactory;
import org.mobicents.protocols.ss7.m3ua.ExchangeType;
import org.mobicents.protocols.ss7.m3ua.Functionality;
import org.mobicents.protocols.ss7.m3ua.IPSPType;
import org.mobicents.protocols.ss7.m3ua.impl.AspImpl;
import org.mobicents.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.mobicents.protocols.ss7.m3ua.parameter.RoutingContext;
import org.mobicents.protocols.ss7.m3ua.parameter.TrafficModeType;
import org.mobicents.protocols.ss7.map.MAPStackImpl;
import org.mobicents.protocols.ss7.map.api.MAPDialog;
import org.mobicents.protocols.ss7.map.api.MAPDialogListener;
import org.mobicents.protocols.ss7.map.api.MAPMessage;
import org.mobicents.protocols.ss7.map.api.MAPMessageType;
import org.mobicents.protocols.ss7.map.api.MAPProvider;
import org.mobicents.protocols.ss7.map.api.MAPServiceListener;
import org.mobicents.protocols.ss7.map.api.dialog.MAPAbortProviderReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPAbortSource;
import org.mobicents.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic;
import org.mobicents.protocols.ss7.map.api.dialog.MAPRefuseReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPUserAbortChoice;
import org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.mobicents.protocols.ss7.map.api.primitives.AddressString;
import org.mobicents.protocols.ss7.map.api.primitives.IMSI;
import org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.mobicents.protocols.ss7.map.api.service.callhandling.IstCommandRequest;
import org.mobicents.protocols.ss7.map.api.service.callhandling.IstCommandResponse;
import org.mobicents.protocols.ss7.map.api.service.callhandling.MAPServiceCallHandlingListener;
import org.mobicents.protocols.ss7.map.api.service.callhandling.ProvideRoamingNumberRequest;
import org.mobicents.protocols.ss7.map.api.service.callhandling.ProvideRoamingNumberResponse;
import org.mobicents.protocols.ss7.map.api.service.callhandling.SendRoutingInformationRequest;
import org.mobicents.protocols.ss7.map.api.service.callhandling.SendRoutingInformationResponse;
import org.mobicents.protocols.ss7.map.api.service.lsm.MAPServiceLsmListener;
import org.mobicents.protocols.ss7.map.api.service.lsm.ProvideSubscriberLocationRequest;
import org.mobicents.protocols.ss7.map.api.service.lsm.ProvideSubscriberLocationResponse;
import org.mobicents.protocols.ss7.map.api.service.lsm.SendRoutingInfoForLCSRequest;
import org.mobicents.protocols.ss7.map.api.service.lsm.SendRoutingInfoForLCSResponse;
import org.mobicents.protocols.ss7.map.api.service.lsm.SubscriberLocationReportRequest;
import org.mobicents.protocols.ss7.map.api.service.lsm.SubscriberLocationReportResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.MAPServiceMobilityListener;
import org.mobicents.protocols.ss7.map.api.service.mobility.authentication.AuthenticationFailureReportRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.authentication.AuthenticationFailureReportResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.authentication.SendAuthenticationInfoRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.authentication.SendAuthenticationInfoResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.faultRecovery.ForwardCheckSSIndicationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.faultRecovery.ResetRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.faultRecovery.RestoreDataRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.faultRecovery.RestoreDataResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.imei.CheckImeiRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.imei.CheckImeiResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.CancelLocationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.CancelLocationResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.PurgeMSRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.PurgeMSResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.SendIdentificationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.SendIdentificationResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.UpdateGprsLocationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.UpdateGprsLocationResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.UpdateLocationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.UpdateLocationResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.oam.ActivateTraceModeRequest_Mobility;
import org.mobicents.protocols.ss7.map.api.service.mobility.oam.ActivateTraceModeResponse_Mobility;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeInterrogationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeInterrogationResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.ProvideSubscriberInfoRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.ProvideSubscriberInfoResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.DeleteSubscriberDataRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.DeleteSubscriberDataResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.InsertSubscriberDataRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.InsertSubscriberDataResponse;
import org.mobicents.protocols.ss7.map.api.service.oam.ActivateTraceModeRequest_Oam;
import org.mobicents.protocols.ss7.map.api.service.oam.ActivateTraceModeResponse_Oam;
import org.mobicents.protocols.ss7.map.api.service.oam.MAPServiceOamListener;
import org.mobicents.protocols.ss7.map.api.service.oam.SendImsiRequest;
import org.mobicents.protocols.ss7.map.api.service.oam.SendImsiResponse;
import org.mobicents.protocols.ss7.map.api.service.pdpContextActivation.MAPServicePdpContextActivationListener;
import org.mobicents.protocols.ss7.map.api.service.pdpContextActivation.SendRoutingInfoForGprsRequest;
import org.mobicents.protocols.ss7.map.api.service.pdpContextActivation.SendRoutingInfoForGprsResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.AlertServiceCentreRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.AlertServiceCentreResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.ForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.InformServiceCentreRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.MAPServiceSmsListener;
import org.mobicents.protocols.ss7.map.api.service.sms.MoForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.MoForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.MtForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.MtForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.NoteSubscriberPresentRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ReadyForSMRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ReadyForSMResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.ReportSMDeliveryStatusRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ReportSMDeliveryStatusResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ActivateSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ActivateSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.DeactivateSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.DeactivateSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.EraseSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.EraseSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.GetPasswordRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.GetPasswordResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.InterrogateSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.InterrogateSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.MAPServiceSupplementaryListener;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.RegisterPasswordRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.RegisterPasswordResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.RegisterSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.RegisterSSResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyResponse;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSRequest;
import org.mobicents.protocols.ss7.map.api.service.supplementary.UnstructuredSSResponse;
import org.mobicents.protocols.ss7.mtp.Mtp3;
import org.mobicents.protocols.ss7.mtp.Mtp3PausePrimitive;
import org.mobicents.protocols.ss7.mtp.Mtp3ResumePrimitive;
import org.mobicents.protocols.ss7.mtp.Mtp3StatusPrimitive;
import org.mobicents.protocols.ss7.mtp.Mtp3TransferPrimitive;
import org.mobicents.protocols.ss7.mtp.Mtp3TransferPrimitiveFactory;
import org.mobicents.protocols.ss7.mtp.Mtp3UserPart;
import org.mobicents.protocols.ss7.mtp.Mtp3UserPartListener;
import org.mobicents.protocols.ss7.sccp.LongMessageRule;
import org.mobicents.protocols.ss7.sccp.LongMessageRuleType;
import org.mobicents.protocols.ss7.sccp.RemoteSccpStatus;
import org.mobicents.protocols.ss7.sccp.SccpListener;
import org.mobicents.protocols.ss7.sccp.SccpProvider;
import org.mobicents.protocols.ss7.sccp.SignallingPointStatus;
import org.mobicents.protocols.ss7.sccp.impl.SccpStackImpl;
import org.mobicents.protocols.ss7.sccp.impl.message.EncodingResultData;
import org.mobicents.protocols.ss7.sccp.impl.message.SccpMessageImpl;
import org.mobicents.protocols.ss7.sccp.message.ParseException;
import org.mobicents.protocols.ss7.sccp.message.SccpDataMessage;
import org.mobicents.protocols.ss7.sccp.message.SccpNoticeMessage;
import org.mobicents.protocols.ss7.sccp.parameter.SccpAddress;
import org.mobicents.protocols.ss7.tcap.api.TCListener;
import org.mobicents.protocols.ss7.tcap.api.tc.dialog.Dialog;
import org.mobicents.protocols.ss7.tcap.api.tc.dialog.events.TCBeginIndication;
import org.mobicents.protocols.ss7.tcap.api.tc.dialog.events.TCContinueIndication;
import org.mobicents.protocols.ss7.tcap.api.tc.dialog.events.TCEndIndication;
import org.mobicents.protocols.ss7.tcap.api.tc.dialog.events.TCNoticeIndication;
import org.mobicents.protocols.ss7.tcap.api.tc.dialog.events.TCPAbortIndication;
import org.mobicents.protocols.ss7.tcap.api.tc.dialog.events.TCUniIndication;
import org.mobicents.protocols.ss7.tcap.api.tc.dialog.events.TCUserAbortIndication;
import org.mobicents.protocols.ss7.tcap.asn.ApplicationContextName;
import org.mobicents.protocols.ss7.tcap.asn.ApplicationContextNameImpl;
import org.mobicents.protocols.ss7.tcap.asn.DialogAPDU;
import org.mobicents.protocols.ss7.tcap.asn.DialogAPDUType;
import org.mobicents.protocols.ss7.tcap.asn.DialogPortion;
import org.mobicents.protocols.ss7.tcap.asn.DialogRequestAPDU;
import org.mobicents.protocols.ss7.tcap.asn.DialogRequestAPDUImpl;
import org.mobicents.protocols.ss7.tcap.asn.DialogResponseAPDU;
import org.mobicents.protocols.ss7.tcap.asn.ErrorCodeImpl;
import org.mobicents.protocols.ss7.tcap.asn.OperationCodeImpl;
import org.mobicents.protocols.ss7.tcap.asn.ProblemImpl;
import org.mobicents.protocols.ss7.tcap.asn.TcapFactory;
import org.mobicents.protocols.ss7.tcap.asn.Utils;
import org.mobicents.protocols.ss7.tcap.asn.comp.Component;
import org.mobicents.protocols.ss7.tcap.asn.comp.Invoke;
import org.mobicents.protocols.ss7.tcap.asn.comp.Parameter;
import org.mobicents.protocols.ss7.tcap.asn.comp.Problem;
import org.mobicents.protocols.ss7.tcap.asn.comp.Reject;
import org.mobicents.protocols.ss7.tcap.asn.comp.ReturnError;
import org.mobicents.protocols.ss7.tcap.asn.comp.TCAbortMessage;
import org.mobicents.protocols.ss7.tcap.asn.comp.TCBeginMessage;
import org.mobicents.protocols.ss7.tcap.asn.comp.TCContinueMessage;
import org.mobicents.protocols.ss7.tcap.asn.comp.TCEndMessage;
import org.mobicents.protocols.ss7.tcap.asn.comp.TCUniMessage;
import org.mobicents.protocols.ss7.tools.simulator.level1.M3UAManagementProxyImpl;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Random;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.TimeUnit;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import javax.xml.bind.DatatypeConverter;
import net.jodah.expiringmap.ExpiringMap;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.authentication.BasicAuthenticator;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.json.simple.JSONObject;
import org.mobicents.protocols.api.Association;
import org.mobicents.protocols.api.ManagementEventListener;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.ss7.indicator.NatureOfAddress;
import org.mobicents.protocols.ss7.indicator.RoutingIndicator;
import org.mobicents.protocols.ss7.m3ua.impl.parameter.ParameterFactoryImpl;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContext;
import org.mobicents.protocols.ss7.map.api.MAPParsingComponentException;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeSubscriptionInterrogationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeSubscriptionInterrogationResponse;
import org.mobicents.protocols.ss7.map.service.callhandling.ProvideRoamingNumberRequestImpl;
import org.mobicents.protocols.ss7.map.service.mobility.locationManagement.CancelLocationRequestImpl;
import org.mobicents.protocols.ss7.map.service.mobility.subscriberInformation.ProvideSubscriberInfoRequestImpl;
import org.mobicents.protocols.ss7.map.service.mobility.subscriberManagement.DeleteSubscriberDataRequestImpl;
import org.mobicents.protocols.ss7.map.service.mobility.subscriberManagement.InsertSubscriberDataRequestImpl;
import org.mobicents.protocols.ss7.mtp.Mtp3EndCongestionPrimitive;
import org.mobicents.protocols.ss7.sccp.NetworkIdState;
import org.mobicents.protocols.ss7.sccp.impl.message.MessageFactoryImpl;
import org.mobicents.protocols.ss7.sccp.impl.message.SccpDataMessageImpl;
import org.mobicents.protocols.ss7.sccp.impl.message.SccpNoticeMessageImpl;
import org.mobicents.protocols.ss7.sccp.message.SccpMessage;
import org.mobicents.protocols.ss7.sccp.parameter.GlobalTitle;
import org.mobicents.protocols.ss7.sccp.parameter.ParameterFactory;
import org.mobicents.protocols.ss7.sccp.parameter.ReturnCause;
import org.mobicents.protocols.ss7.sccp.parameter.ReturnCauseValue;
import org.mobicents.protocols.ss7.tcap.api.TCAPStack;
import org.mobicents.protocols.ss7.tcap.asn.EncodeException;
import org.mobicents.protocols.ss7.tcap.asn.InvokeImpl;
import org.mobicents.protocols.ss7.tcap.asn.ReturnResultLastImpl;
import org.mobicents.protocols.ss7.tcap.asn.UserInformation;
import org.mobicents.protocols.ss7.tcap.asn.UserInformationImpl;
import org.mobicents.protocols.ss7.tcap.asn.comp.ComponentType;
import static org.mobicents.protocols.ss7.tcap.asn.comp.ComponentType.ReturnResultLast;
import org.mobicents.protocols.ss7.tcap.asn.comp.OperationCode;
import org.mobicents.protocols.ss7.tcap.asn.comp.ReturnResultLast;
import static ss7fw.SS7FirewallConfig.called_gt_encryption;
import static ss7fw.SS7FirewallConfig.firewallPolicy;
import static ss7fw.SS7FirewallConfig.keyFactory;
import sigfw.connectorIDS.ConnectorIDS;
import sigfw.connectorIDS.ConnectorIDSModuleRest;
import sigfw.connectorMThreat.ConnectorMThreat;
import sigfw.connectorMThreat.ConnectorMThreatModuleRest;
//import org.mobicents.protocols.ss7.mtp.Mtp3EndCongestionPrimitive;
//import org.mobicents.protocols.ss7.sccp.NetworkIdState;

/**
 * Main SS7Firewall class. Class contains mainly static variables used to build the SS7 stacks.
 * 
 * @author Martin Kacer
 */
public class SS7Firewall implements ManagementEventListener, Mtp3UserPartListener, SccpListener, TCListener, MAPServiceListener, MAPDialogListener, MAPServiceSupplementaryListener, MAPServiceMobilityListener, MAPServiceCallHandlingListener, MAPServiceLsmListener, MAPServiceOamListener, MAPServicePdpContextActivationListener, MAPServiceSmsListener {

    private static Logger logger = Logger.getLogger(SS7Firewall.class);
    private static final ParameterFactoryImpl factory = new ParameterFactoryImpl();
    private static final int NETWORK_INDICATOR = 2;  // used for SCCP router, just used for passive decoding
    private static final int SSN = 0;  // used for MAP stack, just used for passive decoding

    // Unit Tests flags
    public static boolean unitTesting = false;
    public static boolean unitTestingFlags_sendSccpErrorMessage = false;
    public static boolean unitTestingFlags_sendSccpMessage = false;
    
    // SCTP
    private static ManagementImpl sctpManagement;

    // M3UA
    private static M3UAManagementImpl serverM3UAMgmt;
    private static M3UAManagementImpl clientM3UAMgmt;

    // SCCP
    public static SccpStackImpl sccpStack;
    private static SccpProvider sccpProvider;
    private static MessageFactoryImpl sccpMessageFactory;
  
    // TCAP
    private static TCAPStack tcapStack;

    // MAP
    private static MAPStackImpl mapStack;
    private static MAPProvider mapProvider;
    
    static final private String persistDir = "XmlSctpFirewall";
    static private String configName = "ss7fw.json";
    
    // API
    private static Server jettyServer;
    
    // M3UA FIFO
    //public static ArrayDeque<String> m3ua_fifo = new ArrayDeque<String>();
    //private static int m3ua_fifo_max_size = 10000;
    
    // IDS API
    private static ConnectorIDS connectorIDS = null;
    
    // mThreat API
    static ConcurrentLinkedDeque<String> mThreat_alerts = new ConcurrentLinkedDeque<String>();
    private static ConnectorMThreat connectorMThreat = null;
    
    // Honeypot GT NAT
    // Session Key: Original_calling_GT:Original_called_GT (from Invoke)
    // Value: Original_called_GT:Original_dest_SSN
    private Map<String, String> dnat_sessions = null;
    
    // Encryption Autodiscovery
    // Just store first N (encryption_autodiscovery_digits) digits of GT to do not spam the foreign PLMN
    // Key: Called_GT
    // Value: TID
    private final static int encryption_autodiscovery_digits = 6;
    private static Map<String, Long> encryption_autodiscovery_sessions = ExpiringMap.builder()
                                                .expiration(60, TimeUnit.SECONDS)
                                                .build();
    
    // TCAP signature and decryption time window used for TVP
    private final static long tcap_tvp_time_window = 30;  // in seconds
    
    static Random randomGenerator = new Random();
    
    static final private Long OC_SIGNATURE = 100L;
    static final private Long OC_AUTO_ENCRYPTION = 99L;
    
    /**
     * Reset Unit Testing Flags
     */
    public void resetUnitTestingFlags() {
        unitTestingFlags_sendSccpErrorMessage = false;
        unitTestingFlags_sendSccpMessage = false;
    }
    
    /**
     * Initialize SCTP layer
     * 
     * @param ipChannelType TCP or UDP
     */
    private void initSCTP(IpChannelType ipChannelType) throws Exception {
        logger.debug("Initializing SCTP Stack ....");
        this.sctpManagement = new ManagementImpl(
                (String)SS7FirewallConfig.get("$.sigfw_configuration.sctp.sctp_management_name")
        );
        this.sctpManagement.setSingleThread(false);
        
        this.sctpManagement.setPersistDir(persistDir);
        
        this.sctpManagement.start();
        this.sctpManagement.setConnectDelay(10000);
        this.sctpManagement.setMaxIOErrors(30);
        this.sctpManagement.removeAllResourses();
        this.sctpManagement.addManagementEventListener(this);

        // 1. Create SCTP Server
        List<Map<String, Object>> sctp_server = SS7FirewallConfig.get("$.sigfw_configuration.sctp.sctp_server");
        for (int i = 0; i < sctp_server.size(); i++) {
            sctpManagement.addServer(
                    (String)sctp_server.get(i).get("server_name"),
                    (String)sctp_server.get(i).get("host_address"),
                    Integer.parseInt((String)sctp_server.get(i).get("port")),
                    ipChannelType, null
            );
        }
        
        // 2. Create SCTP Server Association
        List<Map<String, Object>> sctp_server_association = SS7FirewallConfig.get("$.sigfw_configuration.sctp.sctp_server_association");
        for (int i = 0; i < sctp_server_association.size(); i++) {
            sctpManagement.addServerAssociation(
                    (String)sctp_server_association.get(i).get("peer_address"),
                    Integer.parseInt((String)sctp_server_association.get(i).get("peer_port")),
                    (String)sctp_server_association.get(i).get("server_name"),
                    (String)sctp_server_association.get(i).get("assoc_name"),
                    ipChannelType
            );
        }
        
        
        // 3. Create SCTP Client Association
        List<Map<String, Object>> sctp_association = SS7FirewallConfig.get("$.sigfw_configuration.sctp.sctp_association");
        for (int i = 0; i < sctp_association.size(); i++) {
            sctpManagement.addAssociation(
                    (String)sctp_association.get(i).get("host_address"),
                    Integer.parseInt((String)sctp_association.get(i).get("host_port")),
                    (String)sctp_association.get(i).get("peer_address"),
                    Integer.parseInt((String)sctp_association.get(i).get("peer_port")),
                    (String)sctp_association.get(i).get("assoc_name"),
                    ipChannelType,
                    null
            );
        }
        
        // 4. Start Server
        for (int i = 0; i < sctp_server.size(); i++) {
            sctpManagement.startServer(
                    (String)sctp_server.get(i).get("server_name")
            );
        }
        
        logger.debug("Initialized SCTP Stack ....");
    }

    /**
     * Initialize M3UA layer
     * 
     */
    private void initM3UA() throws Exception {
        logger.debug("Initializing M3UA Stack ....");
        this.serverM3UAMgmt = new M3UAManagementProxyImpl(
                (String)SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_server.m3ua_management_name")
        );
        
        this.serverM3UAMgmt.setPersistDir(persistDir);
        
        this.serverM3UAMgmt.setTransportManagement(this.sctpManagement);
        
        this.serverM3UAMgmt.start();
        this.serverM3UAMgmt.removeAllResourses();

        // Step 1 : Create App Server
        RoutingContext rc = factory.createRoutingContext(new long[]{100l});
        TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);
        As as = this.serverM3UAMgmt.createAs( 
                (String)SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_server.as_name"),
                Functionality.SGW, ExchangeType.SE, IPSPType.CLIENT, rc, trafficModeType, 1, null
        );

        // Step 2 : Create ASP
        AspFactory aspFactor = this.serverM3UAMgmt.createAspFactory(
                (String)SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_server.asp_name"),
                (String)SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_server.sctp_assoc_name")
        );

        // Step3 : Assign ASP to AS
        AspImpl asp = this.serverM3UAMgmt.assignAspToAs(
                (String)SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_server.as_name"),
                (String)SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_server.asp_name")
        );

        // Step 4: Add Route. Server remote point code
        for (int i = 0; i < SS7FirewallConfig.m3ua_server_remote_pc.size(); i++) {
            this.serverM3UAMgmt.addRoute(Integer.parseInt(SS7FirewallConfig.m3ua_server_remote_pc.get(i)), -1, -1, (String)SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_server.as_name"));
        }
        logger.debug("Initialized M3UA Stack Firewall Server ....");
        
        
        this.clientM3UAMgmt = new M3UAManagementProxyImpl(
                (String)SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_client.m3ua_management_name")
        );
        
        this.clientM3UAMgmt.setPersistDir(persistDir);
        
        this.clientM3UAMgmt.setTransportManagement(this.sctpManagement);
        this.clientM3UAMgmt.start();
        this.clientM3UAMgmt.removeAllResourses();

        // m3ua as create rc <rc> <ras-name>
        RoutingContext rcClient = factory.createRoutingContext(new long[]{100l});
        TrafficModeType trafficModeTypeClient = factory.createTrafficModeType(TrafficModeType.Loadshare);
        this.clientM3UAMgmt.createAs(
                (String)SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_client.as_name"),
                Functionality.AS, ExchangeType.SE, IPSPType.CLIENT, rcClient, trafficModeTypeClient, 1, null
        );

        // Step 2 : Create ASP
        this.clientM3UAMgmt.createAspFactory(
                (String)SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_client.asp_name"),
                (String)SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_client.sctp_assoc_name")
        );

        // Step3 : Assign ASP to AS
        AspImpl aspClient = this.clientM3UAMgmt.assignAspToAs(
                (String)SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_client.as_name"),
                (String)SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_client.asp_name")
        );

        // Step 4: Add Route. Client remote point code
        for (int i = 0; i < SS7FirewallConfig.m3ua_client_remote_pc.size(); i++) {
            this.clientM3UAMgmt.addRoute(Integer.parseInt(SS7FirewallConfig.m3ua_client_remote_pc.get(i)), -1, -1, (String)SS7FirewallConfig.get("$.sigfw_configuration.m3ua.m3ua_client.as_name"));
        }
        
        // Listeners
        serverM3UAMgmt.addMtp3UserPartListener(this);
        clientM3UAMgmt.addMtp3UserPartListener(this);
        
        logger.debug("Initialized M3UA Stack Firewall Client....");
    }

    /**
     * Initialize SCCP layer. SCCP stack is in preview mode, which means
     * the stack does not actively response or SCCP routing. All the the
     * SCCP logic is implemented in onMessage.
     * 
     */
    private void initSCCP() throws Exception {
        logger.debug("Initializing SCCP Stack ....");
        this.sccpStack = new SccpStackImpl("SctpFirewallSCCP");
        this.sccpStack.setMtp3UserPart(1, this.clientM3UAMgmt);
        this.sccpStack.setMtp3UserPart(2, this.serverM3UAMgmt);
        
        this.sccpStack.setPersistDir(persistDir);
        
        this.sccpStack.start();
        this.sccpStack.removeAllResourses();
        
        int j = 0;
        // Server remote point code
        for (int i = 0; i < SS7FirewallConfig.m3ua_server_remote_pc.size(); i++) {
            this.sccpStack.getSccpResource().addRemoteSpc(j, Integer.parseInt(SS7FirewallConfig.m3ua_server_remote_pc.get(i)), 0, 0);
            this.sccpStack.getRouter().addMtp3ServiceAccessPoint(j, 2, Integer.parseInt(SS7FirewallConfig.m3ua_server_remote_pc.get(i)), NETWORK_INDICATOR, 0);
            for (int k = 0; k < SS7FirewallConfig.m3ua_client_remote_pc.size(); k++) {
                //System.out.println("Server i " + i + " j " + j + " k " + k + " " + m3ua_client_remote_pc.get(k));
                this.sccpStack.getRouter().addMtp3Destination(j, 1, Integer.parseInt(SS7FirewallConfig.m3ua_client_remote_pc.get(k)), Integer.parseInt(SS7FirewallConfig.m3ua_client_remote_pc.get(k)), 0, 255, 255);
            }
            j++;
        }
        // Client remote point code
        for (int i = 0; i < SS7FirewallConfig.m3ua_client_remote_pc.size(); i++) {
            this.sccpStack.getSccpResource().addRemoteSpc(j, Integer.parseInt(SS7FirewallConfig.m3ua_client_remote_pc.get(i)), 0, 0);
            this.sccpStack.getRouter().addMtp3ServiceAccessPoint(j, 1, Integer.parseInt(SS7FirewallConfig.m3ua_client_remote_pc.get(i)), NETWORK_INDICATOR, 0);
            for (int k = 0; k < SS7FirewallConfig.m3ua_server_remote_pc.size(); k++) {
                //System.out.println("Client i " + i + " j " + j + " k " + k + " " + m3ua_server_remote_pc.get(k));
                this.sccpStack.getRouter().addMtp3Destination(j, 2, Integer.parseInt(SS7FirewallConfig.m3ua_server_remote_pc.get(k)), Integer.parseInt(SS7FirewallConfig.m3ua_server_remote_pc.get(k)), 0, 255, 255);
            }
            j++;
        }
        
        // TCAP encryption
        // Specify the SCCP message type used by TCAP encryption
        this.sccpStack.getRouter().addLongMessageRule(1, 1, 2, LongMessageRuleType.XUDT_ENABLED);
        
        this.sccpStack.setPreviewMode(true);
        
        this.sccpProvider = this.sccpStack.getSccpProvider();
        this.sccpProvider.registerSccpListener(6, this);
        
        this.sccpMessageFactory = new MessageFactoryImpl(this.sccpStack);

        
   /*     // SCCP routing table
        this.sccpProvider = this.sccpStack.getSccpProvider();
        
        this.sccpProvider.registerSccpListener(6, this);
        this.sccpProvider.registerSccpListener(7, this);
        this.sccpProvider.registerSccpListener(8, this);
        
        GlobalTitle gt;
        String mask;
        
        // gt = this.sccpProvider.getParameterFactory().createGlobalTitle("", 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_MOBILE, null, NatureOfAddress.INTERNATIONAL);
        gt = this.sccpProvider.getParameterFactory().createGlobalTitle("11111111111", 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null, NatureOfAddress.INTERNATIONAL);
              
        
        this.sccpStack.getRouter().addRoutingAddress(1, this.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, SERVER_SPC, 0));
        this.sccpStack.getRouter().addRoutingAddress(2, this.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, gt, CLIENT_SPC, 6));
        this.sccpStack.getRouter().addRoutingAddress(3, this.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, gt, CLIENT_SPC, 7));
        this.sccpStack.getRouter().addRoutingAddress(4, this.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, gt, CLIENT_SPC, 8));

        SccpAddress pattern;
        gt = this.sccpProvider.getParameterFactory().createGlobalTitle("11111111111", 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null, NatureOfAddress.INTERNATIONAL);
        
      //  mask = "*";
      //  pattern = this.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, 8);
      //  ((RouterImpl) this.sccpStack.getRouter()).addRule(1, RuleType.SOLITARY, null, OriginationType.ALL, pattern, mask, 1, -1, null, 0);
      // 
        
        mask = "*";
        pattern = this.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, 8);
        ((RouterImpl) this.sccpStack.getRouter()).addRule(1, RuleType.SOLITARY, null, OriginationType.LOCAL, pattern, mask, 1, -1, null, 0);
        pattern = this.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, 6);
        ((RouterImpl) this.sccpStack.getRouter()).addRule(2, RuleType.SOLITARY, null, OriginationType.LOCAL, pattern, mask, 1, -1, null, 0);
        pattern = this.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, 7);
        ((RouterImpl) this.sccpStack.getRouter()).addRule(3, RuleType.SOLITARY, null, OriginationType.LOCAL, pattern, mask, 1, -1, null, 0);
                
        
        mask = "*";
        pattern = this.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, 6);
        ((RouterImpl) this.sccpStack.getRouter()).addRule(4, RuleType.SOLITARY, null, OriginationType.REMOTE, pattern, mask, 1, -1, null, 0);
        pattern = this.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, 7);
        ((RouterImpl) this.sccpStack.getRouter()).addRule(5, RuleType.SOLITARY, null, OriginationType.REMOTE, pattern, mask, 1, -1, null, 0);
        pattern = this.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, 8);
        ((RouterImpl) this.sccpStack.getRouter()).addRule(6, RuleType.SOLITARY, null, OriginationType.REMOTE, pattern, mask, 1, -1, null, 0);
     */   
        
        logger.debug("Initialized SCCP Stack ....");
    }

   
    /**
     * Initialize MAP layer. MAP and TCAP stack is only in preview mode. 
     * This means the jSS7 stack does not auto decode TCAP and MAP layer
     * and does not actively respond to errors on this layers. The actual
     * decoding is done inside the onMessage method.
     * 
     * If the MAP listeners methods should be used, the MAP stack should be
     * started by this.mapStack.start().
     * 
     */
    private void initMAP() throws Exception {
        logger.debug("Initializing MAP Stack ....");
        SS7Firewall.mapStack = new MAPStackImpl("SctpFirewallMAP", this.sccpStack.getSccpProvider(), SSN);

        SS7Firewall.tcapStack = SS7Firewall.mapStack.getTCAPStack();
        SS7Firewall.tcapStack.setPreviewMode(true);
        SS7Firewall.tcapStack.getProvider().addTCListener(this);
        
        // TODO uncomment to get MAP listeners
        //this.tcapStack.start();
        //this.tcapStack.setDialogIdleTimeout(60000);
        //this.tcapStack.setInvokeTimeout(30000);
        //this.tcapStack.setMaxDialogs(2000);
        logger.debug("Initialized TCAP Stack ....");
        
        
        this.mapProvider = this.mapStack.getMAPProvider();
        
        this.mapProvider.addMAPDialogListener(this);
        //this.mapProvider.addMAPServiceLitener(this);

        this.mapProvider.getMAPServiceSupplementary().addMAPServiceListener(this);
        this.mapProvider.getMAPServiceSupplementary().acivate();
        
        this.mapProvider.getMAPServiceMobility().addMAPServiceListener(this);
        this.mapProvider.getMAPServiceMobility().acivate();
        
        this.mapProvider.getMAPServiceCallHandling().addMAPServiceListener(this);
        this.mapProvider.getMAPServiceMobility().acivate();
        
        this.mapProvider.getMAPServiceLsm().addMAPServiceListener(this);
        this.mapProvider.getMAPServiceLsm().acivate();
        
        this.mapProvider.getMAPServiceOam().addMAPServiceListener(this);
        this.mapProvider.getMAPServiceOam().acivate();
        
        this.mapProvider.getMAPServicePdpContextActivation().addMAPServiceListener(this);
        this.mapProvider.getMAPServicePdpContextActivation().acivate();
        
        this.mapProvider.getMAPServiceSms().addMAPServiceListener(this);
        this.mapProvider.getMAPServiceSms().acivate();
        
        // TODO uncomment to get MAP listeners
        //this.mapStack.start();
        
        logger.debug("Initialized MAP Stack ....");
    }

    /**
     * Initialize the SS7 stack
     * 
     * @param ipChannelType TCP or UDP
     */
    public void initializeStack(IpChannelType ipChannelType) throws Exception {
        
        if (SS7FirewallConfig.firewallPolicy == SS7FirewallConfig.FirewallPolicy.DNAT_TO_HONEYPOT) {
            dnat_sessions = ExpiringMap.builder()
                                                .expiration(SS7FirewallConfig.honeypot_dnat_session_expiration_timeout, TimeUnit.SECONDS)
                                                .build();
        }   

        this.initSCTP(ipChannelType);

        // Initialize M3UA first
        this.initM3UA();

        // Initialize SCCP
        this.initSCCP();
        
        // Initialize MAP
        this.initMAP();

        // 7. Start ASP
        serverM3UAMgmt.startAsp("RASP1");
        clientM3UAMgmt.startAsp("ASP1");

        logger.debug("[[[[[[[[[[    Started SctpFirewall       ]]]]]]]]]]");
    }   
    
    /**
     * Method to send SCCP error message (UDTS).
     * 
     * @param mup M3UA instance
     * @param opc M3UA OPC
     * @param dpc M3UA DPC
     * @param sls M3UA SLS
     * @param ni M3UA NI
     * @param lmrt LongMessageRuleType
     * @param message Original SCCP message
     * @param returnCauseInt SCCP return cause
     */
    private void sendSccpErrorMessage(Mtp3UserPart mup, int opc, int dpc, int sls, int ni, LongMessageRuleType lmrt, SccpDataMessage message, ReturnCauseValue returnCauseInt) {
        
        if (this.unitTesting == true) {
            this.unitTestingFlags_sendSccpErrorMessage = true;
            return;
        }
        
        SccpNoticeMessage ans = null;
        // not sure if its proper
        ReturnCause returnCause = ((ParameterFactory) this.sccpProvider.getParameterFactory()).createReturnCause(returnCauseInt);

        //SccpDataMessage msgData = (SccpDataMessage) message;
        ans = this.sccpMessageFactory.createNoticeMessage(message.getType(), returnCause,
                message.getCallingPartyAddress(), message.getCalledPartyAddress(), message.getData(), message.getHopCounter(),
                message.getImportance());


        EncodingResultData erd;
        try {
            erd = ((SccpMessageImpl)ans).encode(this.sccpStack, lmrt, mup.getMaxUserDataLength(dpc), logger, this.sccpStack.isRemoveSpc(),
                    this.sccpStack.getSccpProtocolVersion());

            switch (erd.getEncodingResult()) {
                case Success:
                    Mtp3TransferPrimitiveFactory factory = mup.getMtp3TransferPrimitiveFactory();
                    if (erd.getSolidData() != null) {
                        // nonsegmented data
                        Mtp3TransferPrimitive msg = factory.createMtp3TransferPrimitive(Mtp3._SI_SERVICE_SCCP, ni, 0,
                                opc, dpc, sls, erd.getSolidData());
                        mup.sendMessage(msg);
                    } else {
                        // segmented data
                        for (byte[] bf : erd.getSegementedData()) {
                            Mtp3TransferPrimitive msg = factory.createMtp3TransferPrimitive(Mtp3._SI_SERVICE_SCCP, ni, 0,
                                    opc, dpc, sls, bf);
                            mup.sendMessage(msg);
                        }
                    }
            }
        } catch (ParseException ex) {
            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    /**
     * Method to send SCCP data message.
     * 
     * @param mup M3UA instance
     * @param opc M3UA OPC
     * @param dpc M3UA DPC
     * @param sls M3UA SLS
     * @param ni M3UA NI
     * @param lmrt LongMessageRuleType
     * @param message Original SCCP message
     */
    private void sendSccpMessage(Mtp3UserPart mup, int opc, int dpc, int sls, int ni, LongMessageRuleType lmrt, SccpDataMessage message) {
        
        if (this.unitTesting == true) {
            this.unitTestingFlags_sendSccpMessage = true;
            return;
        }
        
        EncodingResultData erd;
        try {
            if (SS7FirewallConfig.firewallPolicy == SS7FirewallConfig.FirewallPolicy.DNAT_TO_HONEYPOT &&  dnat_sessions != null) {
                
                // Reverse NAT from Honeypot (the backward messages)
                if(message.getCallingPartyAddress() != null
                   && message.getCallingPartyAddress().getGlobalTitle() != null
                   && message.getCalledPartyAddress() != null
                   && message.getCalledPartyAddress().getGlobalTitle() != null
                   && message.getCallingPartyAddress().getGlobalTitle().getDigits().equals(SS7FirewallConfig.honeypot_sccp_gt)
                   && dnat_sessions.containsKey(message.getCalledPartyAddress().getGlobalTitle().getDigits())) {
                        String original_gt_ssn = dnat_sessions.get(message.getCalledPartyAddress().getGlobalTitle().getDigits());
                        String[] gt_ssn = original_gt_ssn.split(":");
                        String original_gt = gt_ssn[0];
                        String original_ssn = gt_ssn[1];
                        GlobalTitle gt = this.sccpProvider.getParameterFactory().createGlobalTitle(original_gt, 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null, NatureOfAddress.INTERNATIONAL);
                        SccpAddress sa = this.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, Integer.decode(original_ssn));
                        message.setCallingPartyAddress(sa);
                }
                // Forward NAT towards Honeypot (for latter forward messages not detected as alerts)
                else if(message.getCallingPartyAddress() != null
                   && message.getCallingPartyAddress().getGlobalTitle() != null
                   && message.getCalledPartyAddress() != null
                   && message.getCalledPartyAddress().getGlobalTitle() != null
                   && dnat_sessions.containsKey(message.getCallingPartyAddress().getGlobalTitle().getDigits())) {
                    dnat_sessions.put(message.getCallingPartyAddress().getGlobalTitle().getDigits(), message.getCalledPartyAddress().getGlobalTitle().getDigits() + ":" + message.getCalledPartyAddress().getSubsystemNumber());
                    GlobalTitle gt = this.sccpProvider.getParameterFactory().createGlobalTitle(SS7FirewallConfig.honeypot_sccp_gt, 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null, NatureOfAddress.INTERNATIONAL);
                    SccpAddress sa_dnat = this.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, message.getCalledPartyAddress().getSubsystemNumber());
                    message.setCalledPartyAddress(sa_dnat);
                }
            }
            
            
            erd = ((SccpMessageImpl)message).encode(this.sccpStack, lmrt, mup.getMaxUserDataLength(dpc), logger, this.sccpStack.isRemoveSpc(),
                    this.sccpStack.getSccpProtocolVersion());

            switch (erd.getEncodingResult()) {
                case Success:
                    Mtp3TransferPrimitiveFactory factory = mup.getMtp3TransferPrimitiveFactory();
                    if (erd.getSolidData() != null) {
                        // nonsegmented data
                        Mtp3TransferPrimitive msg = factory.createMtp3TransferPrimitive(Mtp3._SI_SERVICE_SCCP, ni, 0,
                                opc, dpc, sls, erd.getSolidData());
                        mup.sendMessage(msg);
                    } else {
                        // segmented data
                        for (byte[] bf : erd.getSegementedData()) {
                            Mtp3TransferPrimitive msg = factory.createMtp3TransferPrimitive(Mtp3._SI_SERVICE_SCCP, ni, 0,
                                    opc, dpc, sls, bf);
                            mup.sendMessage(msg);
                        }
                    }
            }
        } catch (ParseException ex) {
            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Method to execute firewall policy on target SCCP message.
     * 
     * @param mup M3UA instance in forward direction
     * @param mupReturn M3UA instance in reverse direction, to return UDTS
     * @param opc M3UA OPC
     * @param dpc M3UA DPC
     * @param sls M3UA SLS
     * @param ni M3UA NI
     * @param lmrt LongMessageRuleType
     * @param message Original SCCP message
     * @param reason the reason of discarding the message
     * @param lua_hm the LUA parameters, decoded from the message
     */
    private void firewallMessage(Mtp3UserPart mup, Mtp3UserPart mupReturn, int opc, int dpc, int sls, int ni, LongMessageRuleType lmrt, SccpDataMessage message, String reason, HashMap<String, String> lua_hm) {
        String firewallPolicy = "";
        if (SS7FirewallConfig.firewallPolicy == SS7FirewallConfig.FirewallPolicy.DROP_SILENTLY) {
            firewallPolicy = "DROP_SILENTLY";
        } else if (SS7FirewallConfig.firewallPolicy == SS7FirewallConfig.FirewallPolicy.DROP_WITH_SCCP_ERROR) {
            firewallPolicy = "DROP_WITH_SCCP_ERROR";
            sendSccpErrorMessage(mupReturn, dpc, opc, sls, ni, lmrt, message, ReturnCauseValue.NO_TRANSLATION_FOR_ADDRESS);
        } else if (SS7FirewallConfig.firewallPolicy == SS7FirewallConfig.FirewallPolicy.DNAT_TO_HONEYPOT && dnat_sessions != null
                && message.getCallingPartyAddress() != null
                && message.getCallingPartyAddress().getGlobalTitle() != null 
                && message.getCalledPartyAddress() != null
                && message.getCalledPartyAddress().getGlobalTitle() != null
                ) {
            firewallPolicy = "DNAT_TO_HONEYPOT";
            
            GlobalTitle gt = this.sccpProvider.getParameterFactory().createGlobalTitle(SS7FirewallConfig.honeypot_sccp_gt, 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null, NatureOfAddress.INTERNATIONAL);
            SccpAddress sa_dnat = this.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, message.getCalledPartyAddress().getSubsystemNumber());
            SccpAddress sa = message.getCalledPartyAddress();
            String session_key = message.getCallingPartyAddress().getGlobalTitle().getDigits();
            dnat_sessions.put(session_key, message.getCalledPartyAddress().getGlobalTitle().getDigits() + ":" + message.getCalledPartyAddress().getSubsystemNumber());
            message.setCalledPartyAddress(sa_dnat);
            
            sendSccpMessage(mup, opc, dpc, sls, ni, lmrt, message);
        } else if (SS7FirewallConfig.firewallPolicy == SS7FirewallConfig.FirewallPolicy.ALLOW) {
            firewallPolicy = "ALLOW";
            sendSccpMessage(mup, opc, dpc, sls, ni, lmrt, message);
        }
        
        logger.info("Blocked message: Reason [" + reason + "] Policy [" + firewallPolicy + "] " + message.toString());
        
        JSONObject json_alert = new JSONObject();
        logger.debug("============ LUA variables ============");
        // mThreat alerting
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        
            for (String key : lua_hm.keySet()) {
                logger.debug(key + ": " + lua_hm.get(key));

                String value = lua_hm.get(key);
                // Anonymize MSISDN, IMSI
                if (key.equals("map_imsi") || key.equals("map_msisdn")) {
                    // add salt before hashing
                    value = SS7FirewallConfig.mthreat_salt + value;
                    value = DatatypeConverter.printHexBinary(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
                } 
                json_alert.put(key, value);
            }
            mThreat_alerts.add(json_alert.toJSONString());
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Method remove from SCCP message duplicated TCAP signatures and verifies the TCAP signature.
     * Method currently is designed only for TCAP begin messages.
     * 
     * 
     * @param message SCCP message
     * @param tcb TCAP Begin Message
     * @param comps TCAP Components
     * @return -1 no public key to verify signature, 0 signature does not match, 1 signature ok
     */
    int tcapVerify(SccpDataMessage message, TCBeginMessage tcb, Component[] comps) {
        // --------------- TCAP verify  ---------------
        int signature_ok = -1;  // no key
        PublicKey publicKey = SS7FirewallConfig.simpleWildcardFind(SS7FirewallConfig.calling_gt_verify, message.getCallingPartyAddress().getGlobalTitle().getDigits());
        if (publicKey != null) {

            signature_ok = 0;

            List<Integer> signed_index = new ArrayList<Integer>();
            for (int i = 0; i < comps.length; i++) {
                // find all signature components
                if (comps[i].getType() == ComponentType.Invoke) {
                    Invoke inv = (Invoke) comps[i];
                    if (inv.getOperationCode().getLocalOperationCode() == OC_SIGNATURE) {
                        signed_index.add(i);
                    }
                }
            }
            if (signed_index.size() > 0) {
                // read signature component
                InvokeImpl invSignature = (InvokeImpl)comps[signed_index.get(0)];
                Parameter p = invSignature.getParameter();
                Parameter[] pa;
                
                // Signature
                byte[] signatureBytes = null;
                long t_tvp = 0;
                 
                if (p != null && p.getTagClass() == Tag.CLASS_UNIVERSAL) {
                    pa = p.getParameters();


                    // Reserved (currently not used) - Signature Version
                    // TODO
                    if (pa.length >= 1) {
                        
                    }

                    // TVP
                    if (pa.length >= 2) {
                        byte[] TVP = {0x00, 0x00, 0x00, 0x00};
                        // ---- Verify TVP from Security header ----
                        long t = System.currentTimeMillis()/100;    // in 0.1s
                        TVP[0] = (byte) ((t >> 24) & 0xFF);
                        TVP[1] = (byte) ((t >> 16) & 0xFF);
                        TVP[2] = (byte) ((t >>  8) & 0xFF);
                        TVP[3] = (byte) ((t >>  0) & 0xFF);
                        t = 0;
                        for (int i = 0; i < TVP.length; i++) {
                            t =  ((t << 8) + (TVP[i] & 0xff));
                        }
                        
                        TVP = pa[1].getData();
                        for (int i = 0; i < TVP.length; i++) {
                            t_tvp =  ((t_tvp << 8) + (TVP[i] & 0xff));
                        }
                        if (Math.abs(t_tvp-t) > tcap_tvp_time_window*10) {
                            logger.info("TCAP FW: TCAP verify signature. Wrong timestamp in TVP (received: " + t_tvp + ", current: " + t + ")");
                            return 0;
                        }
                        // ---- End of Verify TVP ----
                    }

                    // Signature
                    if (pa.length >= 3) {
                        if (pa[2].getTagClass() == Tag.CLASS_PRIVATE && pa[2].getTag() == Tag.STRING_OCTET) {
                            signatureBytes = pa[2].getData();
                        }
                    }
                }

                // remove all signature components
                Component[] c = new Component[comps.length - signed_index.size()];
                for (int i = 0; i < comps.length - signed_index.size(); i++) {
                    if (!signed_index.contains(i)) {
                        c[i] = comps[i];
                    }
                }

                tcb.setComponent(c);
                AsnOutputStream aos = new AsnOutputStream();
                try {
                    tcb.encode(aos);
                } catch (EncodeException ex) {
                    java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                }

                byte[] _d = aos.toByteArray();
                message.setData(_d);
                String dataToSign = "";

                // verify signature
                try {
                    comps = c;
                    dataToSign = message.getCallingPartyAddress().getGlobalTitle().getDigits()
                            + message.getCalledPartyAddress().getGlobalTitle().getDigits() + t_tvp;
                    for (int i = 0; i < comps.length; i++) {
                        AsnOutputStream _aos = new AsnOutputStream();
                        try {
                            comps[i].encode(_aos);
                            dataToSign += Base64.getEncoder().encodeToString(_aos.toByteArray());
                        } catch (EncodeException ex) {
                            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }

                    SS7FirewallConfig.signature.initVerify(publicKey);
                    SS7FirewallConfig.signature.update(dataToSign.getBytes());
                    if (signatureBytes != null && SS7FirewallConfig.signature.verify(signatureBytes)) {
                        signature_ok = 1;
                    }

                } catch (InvalidKeyException ex) {
                    java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (SignatureException ex) {
                    java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                }

                logger.debug("Removing TCAP Signed Data: " + dataToSign);
                if (signatureBytes != null) {
                    logger.debug("Removing TCAP Signature: " + Base64.getEncoder().encodeToString(signatureBytes));
                }
            }
        }
        return signature_ok;
        // --------------------------------------------
    }
    
    /**
     * Method to add TCAP signature into SCCP message.
     * Method currently is designed only for TCAP begin messages.
     * 
     * 
     * @param message SCCP message
     * @param tcb TCAP Begin Message
     * @param comps TCAP Components
     * @param lmrt Long Message Rule Type, if UDT or XUDT should be send
     * @return Long Message Rule Type, , if UDT or XUDT should be send
     */
    LongMessageRuleType tcapSign(SccpDataMessage message, TCBeginMessage tcb, Component[] comps, LongMessageRuleType lmrt) {
        // --------------- TCAP signing ---------------
        LongMessageRuleType l = lmrt;
        
        KeyPair keyPair = SS7FirewallConfig.simpleWildcardFind(SS7FirewallConfig.calling_gt_signing, message.getCallingPartyAddress().getGlobalTitle().getDigits());
        if (keyPair != null) {
            PrivateKey privateKey = keyPair.getPrivate();
            
            Component[] c = new Component[comps.length + 1];
            int i;
            boolean signed = false;
            for (i = 0; i < comps.length; i++) {
                c[i] = comps[i];
                // already signed check
                if (c[i].getType() == ComponentType.Invoke) {
                    Invoke inv = (Invoke) comps[i];
                    if (inv.getOperationCode().getLocalOperationCode() == OC_SIGNATURE) {
                        signed = true;
                    }
                }
            }
            if (!signed) {
                c[i] = new InvokeImpl();
                ((InvokeImpl)c[i]).setInvokeId(1l);
                OperationCode oc = TcapFactory.createOperationCode();
                oc.setLocalOperationCode(OC_SIGNATURE);
                ((InvokeImpl)c[i]).setOperationCode(oc);
                
                // Reserved (currently not used) - Signature Version
                // TODO
                Parameter p1 = TcapFactory.createParameter();
                p1.setTagClass(Tag.CLASS_PRIVATE);
                p1.setPrimitive(true);
                p1.setTag(Tag.STRING_OCTET);
                p1.setData("v1".getBytes());

                // TVP
                byte[] TVP = {0x00, 0x00, 0x00, 0x00};
                        
                long t = System.currentTimeMillis()/100;    // in 0.1s
                TVP[0] = (byte) ((t >> 24) & 0xFF);
                TVP[1] = (byte) ((t >> 16) & 0xFF);
                TVP[2] = (byte) ((t >>  8) & 0xFF);
                TVP[3] = (byte) ((t >>  0) & 0xFF);
                
                long t_tvp = 0;
                for (int j = 0; j < TVP.length; j++) {
                    t_tvp =  ((t_tvp << 8) + (TVP[j] & 0xff));
                }
                
                Parameter p2 = TcapFactory.createParameter();
                p2.setTagClass(Tag.CLASS_PRIVATE);
                p2.setPrimitive(true);
                p2.setTag(Tag.STRING_OCTET);
                p2.setData(TVP);               
                
                // Signature
                Parameter p3 = TcapFactory.createParameter();
                p3.setTagClass(Tag.CLASS_PRIVATE);
                p3.setPrimitive(true);
                p3.setTag(Tag.STRING_OCTET);

                try {
                    SS7FirewallConfig.signature.initSign(privateKey);

                    String dataToSign = message.getCallingPartyAddress().getGlobalTitle().getDigits()
                            + message.getCalledPartyAddress().getGlobalTitle().getDigits() + t_tvp;
                    for (i = 0; i < comps.length; i++) {
                        AsnOutputStream _aos = new AsnOutputStream();
                        try {
                            comps[i].encode(_aos);
                            dataToSign += Base64.getEncoder().encodeToString(_aos.toByteArray());
                        } catch (EncodeException ex) {
                            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }

                    SS7FirewallConfig.signature.update(dataToSign.getBytes());
                    byte[] signatureBytes = SS7FirewallConfig.signature.sign();
                    logger.debug("Adding TCAP Signed Data: " + dataToSign);
                    logger.debug("Adding TCAP Signature: " + Base64.getEncoder().encodeToString(signatureBytes));

                    p3.setData(signatureBytes);

                    Parameter p = TcapFactory.createParameter();
                    p.setTagClass(Tag.CLASS_UNIVERSAL);
                    p.setTag(0x04);
                    p.setParameters(new Parameter[] {p1, p2, p3});
                    
                    ((InvokeImpl)c[i]).setParameter(p);
                    tcb.setComponent(c);
                    AsnOutputStream aos = new AsnOutputStream();
                    try {
                        tcb.encode(aos);
                    } catch (EncodeException ex) {
                        java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                    }

                    byte[] _d = aos.toByteArray();
                    message.setData(_d);

                } catch (InvalidKeyException ex) {
                    java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                } catch (SignatureException ex) {
                    java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        return l;
        // --------------------------------------------
    }
    
    /**
     * Method handling the SCCP messages and executing the firewall logic.
     * The method contains sequence of execution of all firewall rules
     * according the configuration file.
     * 
     * If message hit some firewall blacklist rules the firewall action
     * is performed, otherwise the message is forwarded.
     * 
     * Inside the method also the encryption/decryption and message signing
     * is implemented.
     * 
     * @param message SCCP data message
     */
    @Override
    public void onMessage(SccpDataMessage message) {
        logger.debug("[[[[[[[[[[    Sccp Message Recieved      ]]]]]]]]]]");
        logger.debug(message.toString());

        int dpc = message.getIncomingDpc();
        int opc = message.getIncomingOpc();
        int sls = message.getSls();
        int ni = message.getNetworkId();
        
        Mtp3UserPart mup = this.serverM3UAMgmt;        
        Mtp3UserPart mupReturn = this.clientM3UAMgmt;
        
        // LUA variables
        HashMap<String, String> lua_hmap = new HashMap<String, String>();
        lua_hmap.put("sccp_calling_gt", "");
        lua_hmap.put("sccp_called_gt", "");
        lua_hmap.put("tcap_oc", "");
        lua_hmap.put("tcap_ac", "");
        lua_hmap.put("tcap_tag", "");
        lua_hmap.put("map_imsi", "");
        lua_hmap.put("map_msisdn", "");

        for (int i = 0; i < SS7FirewallConfig.m3ua_server_remote_pc.size(); i++) {
            if (dpc == Integer.parseInt(SS7FirewallConfig.m3ua_server_remote_pc.get(i))) {
                mup = this.serverM3UAMgmt;
                mupReturn = this.clientM3UAMgmt;
                break;
            }
        }
        for (int i = 0; i < SS7FirewallConfig.m3ua_client_remote_pc.size(); i++) {
            if (dpc == Integer.parseInt(SS7FirewallConfig.m3ua_client_remote_pc.get(i))) {
                mup = this.clientM3UAMgmt;
                mupReturn = this.serverM3UAMgmt;
                break;
            }
        }
        
        //LongMessageRule lmr = this.sccpStack.getRouter().findLongMessageRule(dpc);
        LongMessageRule lmr = null;
        for (Map.Entry<Integer, LongMessageRule> e : this.sccpStack.getRouter().getLongMessageRules().entrySet()) {
            LongMessageRule rule = e.getValue();
            if (rule.matches(dpc)) {
                lmr = rule;
                break;
            }
        }
        
        LongMessageRuleType lmrt = LongMessageRuleType.LONG_MESSAGE_FORBBIDEN;
        if (message.getType() == SccpMessage.MESSAGE_TYPE_XUDT) {
            lmrt = LongMessageRuleType.XUDT_ENABLED;
        }
            
        // -------------  SCCP firewall -------------
       
        // Calling GT whitelist and blacklist
        if (message.getCallingPartyAddress() != null
            && message.getCallingPartyAddress().getGlobalTitle() != null) {
            lua_hmap.put("sccp_calling_gt", message.getCallingPartyAddress().getGlobalTitle().getDigits());

            if(SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.sccp_calling_gt_whitelist, message.getCallingPartyAddress().getGlobalTitle().getDigits())) {
                logger.info("============ SCCP Whitelisted Calling GT = " + message.getCallingPartyAddress().getGlobalTitle().getDigits() + " ============");
                sendSccpMessage(mup, opc, dpc, sls, ni, lmrt, message);
                return;
            }
            
            //logger.debug("SCCP Calling GT = " + message.getCallingPartyAddress().getGlobalTitle().getDigits());
            if(SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.sccp_calling_gt_blacklist, message.getCallingPartyAddress().getGlobalTitle().getDigits())) {

                //logger.info("============ SCCP Blocked Calling GT = " + message.getCallingPartyAddress().getGlobalTitle().getDigits() + " ============");
                firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "SCCP FW: Calling GT = " + message.getCallingPartyAddress().getGlobalTitle().getDigits(), lua_hmap);
                return;

            }
        }
        
        if (message.getCalledPartyAddress() != null) { 
            if (message.getCalledPartyAddress().getGlobalTitle() != null) {
                 lua_hmap.put("sccp_called_gt", message.getCalledPartyAddress().getGlobalTitle().getDigits());
            }
        }
        
        
        // ------------ TCAP decryption -------------
        if (message.getType() == SccpDataMessage.MESSAGE_TYPE_XUDT && message.getCalledPartyAddress() != null) { 
            if (message.getCalledPartyAddress().getGlobalTitle() != null) {
                KeyPair keyPair = SS7FirewallConfig.simpleWildcardFind(SS7FirewallConfig.called_gt_decryption, message.getCalledPartyAddress().getGlobalTitle().getDigits());
                if (keyPair != null) {
                    logger.debug("TCAP Decryption for SCCP Called GT = " + message.getCalledPartyAddress().getGlobalTitle().getDigits());
                
                    try {
                        // Sending XUDT message from UDT message
                        
                        // SPI(version) and TVP(timestamp)
                        byte[] SPI = {0x00, 0x00, 0x00, 0x00};
                        byte[] TVP = {0x00, 0x00, 0x00, 0x00};
                        
                        byte[] data = null; 
                        if (message.getData().length >= SPI.length) {
                            SPI = Arrays.copyOfRange(message.getData(), 0, SPI.length);
                            data = Arrays.copyOfRange(message.getData(), SPI.length, message.getData().length);
                        } else {
                            data = message.getData();
                        }
                        
                        PrivateKey privateKey = keyPair.getPrivate();
                        SS7FirewallConfig.cipher.init(Cipher.DECRYPT_MODE, privateKey);
                        
                        RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
                        int keyLength = rsaPublicKey.getModulus().bitLength() / 8;
                        
                        // TODO verify SPI
      
                        byte[][] datas = splitByteArray(data, keyLength/* - 11*/);
                        byte[] decryptedText = null;
                        for (byte[] b : datas) {
                            
                            byte[] d = SS7FirewallConfig.cipher.doFinal(b);
                            // ------- Verify TVP --------
                            long t = System.currentTimeMillis()/100;    // in 0.1s
                            TVP[0] = (byte) ((t >> 24) & 0xFF);
                            TVP[1] = (byte) ((t >> 16) & 0xFF);
                            TVP[2] = (byte) ((t >>  8) & 0xFF);
                            TVP[3] = (byte) ((t >>  0) & 0xFF);
                            t = 0;
                            for (int i = 0; i < TVP.length; i++) {
                                t =  ((t << 8) + (TVP[i] & 0xff));
                            }

                            TVP[0] = d[0]; TVP[1] = d[1]; TVP[2] = d[2]; TVP[3] = d[3];
                            long t_tvp = 0;
                            for (int i = 0; i < TVP.length; i++) {
                                t_tvp =  ((t_tvp << 8) + (TVP[i] & 0xff));
                            }
                            if (Math.abs(t_tvp-t) > tcap_tvp_time_window*10) {
                                firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "TCAP FW: TCAP decryption. Wrong timestamp in TVP (received: " + t_tvp + ", current: " + t + ")", lua_hmap);
                                return;
                            }
                            d = Arrays.copyOfRange(d, TVP.length, d.length);
                            // ---- End of Verify TVP ----
                            
                            
                            decryptedText = concatByteArray(decryptedText, d);
                        }
                        
                        SccpDataMessage m = this.sccpMessageFactory.createDataMessageClass0(message.getCalledPartyAddress(), message.getCallingPartyAddress(), decryptedText, message.getOriginLocalSsn(), false, null, null);
                        message = m;
                    } catch (InvalidKeyException ex) {
                        logger.info("TCAP FW: TCAP decryption failed for SCCP Called GT: " + message.getCalledPartyAddress().getGlobalTitle().getDigits() + " InvalidKeyException: "+ ex.getMessage());
                        //java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IllegalBlockSizeException ex) {
                        logger.info("TCAP FW: TCAP decryption failed for SCCP Called GT: " + message.getCalledPartyAddress().getGlobalTitle().getDigits() + " IllegalBlockSizeException: "+ ex.getMessage());
                        //java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (BadPaddingException ex) {
                        logger.info("TCAP FW: TCAP decryption failed for SCCP Called GT: " + message.getCalledPartyAddress().getGlobalTitle().getDigits() + " BadPaddingException: "+ ex.getMessage());
                        //java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
        }
        // ------------------------------------------
        
        // -------------- TCAP firewall -------------
        // TCAP
        byte[] data = message.getData();
        SccpAddress localAddress = message.getCalledPartyAddress();
        SccpAddress remoteAddress = message.getCallingPartyAddress();
        long dialogId = 0;
        DialogPortion dialogPortion = null;
        ApplicationContextName ACN = null;
        Component[] comps = null;

        // asnData - it should pass
        AsnInputStream ais = new AsnInputStream(data);

        // this should have TC message tag
        int tag;
        try {
            tag = ais.readTag();
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
            
            firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "TCAP FW: Missing TC tag", lua_hmap);
            return;
        }

        if (ais.getTagClass() != Tag.CLASS_APPLICATION) {
            //unrecognizedPackageType(message, localAddress, remoteAddress, ais, tag, message.getNetworkId());
            
            firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "TCAP FW: Unrecognized TC tag", lua_hmap);
            return;
        }

        dialogPortion = null;
        comps = null;

        lua_hmap.put("tcap_tag", new Integer(tag).toString());

        TCContinueMessage tcm = null;
        TCBeginMessage tcb = null;
        TCEndMessage teb = null;
        TCAbortMessage tub = null;
        TCUniMessage tcuni;
        
        switch (tag) {
        // continue first, usually we will get more of those. small perf
        // boost
        case TCContinueMessage._TAG:
            try {
                tcm = TcapFactory.createTCContinueMessage(ais);
            } catch (org.mobicents.protocols.ss7.tcap.asn.ParseException e) {
                logger.debug("ParseException when parsing TCContinueMessage: " + e.toString(), e);
                
                firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "TCAP FW: ParseException when parsing TCContinueMessage", lua_hmap);
                return;
            }

            // TID
            dialogId = Utils.decodeTransactionId(tcm.getDestinationTransactionId());

            // Application Context
            dialogPortion = tcm.getDialogPortion();

            // Operation Code
            comps = tcm.getComponent();

            break;

        case TCBeginMessage._TAG:
            try {
                tcb = TcapFactory.createTCBeginMessage(ais);
            } catch (org.mobicents.protocols.ss7.tcap.asn.ParseException e) {
                logger.debug("ParseException when parsing TCBeginMessage: " + e.toString(), e);
                
                firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "TCAP FW: ParseException when parsing TCBeginMessage", lua_hmap);
                return;
            }
            if (tcb.getDialogPortion() != null && tcb.getDialogPortion().getDialogAPDU() != null
                    && tcb.getDialogPortion().getDialogAPDU() instanceof DialogRequestAPDUImpl) {
                DialogRequestAPDUImpl dlg = (DialogRequestAPDUImpl) tcb.getDialogPortion().getDialogAPDU();
                if (!dlg.getProtocolVersion().isSupportedVersion()) {
                    logger.debug("Unsupported protocol version of  has been received when parsing TCBeginMessage");
                    //this.sendProviderAbort(DialogServiceProviderType.NoCommonDialogPortion, tcb.getOriginatingTransactionId(), remoteAddress, localAddress,
                    //        message.getSls(), dlg.getApplicationContextName(), message.getNetworkId());
                    
                    firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "TCAP FW: Unsupported protocol version of  has been received when parsing TCBeginMessage", lua_hmap);
                    return;
                }
            }

            // TID
            dialogId = Utils.decodeTransactionId(tcb.getOriginatingTransactionId());

            // Application Context
            dialogPortion = tcb.getDialogPortion();
            

            // Operation Code
            comps = tcb.getComponent();

            // --------------- TCAP signature ---------------
            if (comps != null) {
                if (message.getCallingPartyAddress() != null) { 
                    if (message.getCallingPartyAddress().getGlobalTitle() != null) {
                        // --------------- TCAP verify  ---------------
                        if (tcapVerify(message, tcb, comps) == 0) {
                            // Drop not correctly signed messages
                            //logger.info("============ Wrong TCAP signature, message blocked. Calling GT = " + message.getCallingPartyAddress().getGlobalTitle().getDigits() + " ============");

                            firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "TCAP FW: Wrong TCAP signature", lua_hmap);
                            return;
                        }
                        // --------------------------------------------
                    }
                }
            }
            // ------------------------------------------

            break;

        case TCEndMessage._TAG:
            try {
                teb = TcapFactory.createTCEndMessage(ais);
            } catch (org.mobicents.protocols.ss7.tcap.asn.ParseException e) {
                logger.debug("ParseException when parsing TCEndMessage: " + e.toString(), e);
                
                firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "TCAP FW: ParseException when parsing TCEndMessage", lua_hmap);
                return;
            }

            // TID
            dialogId = Utils.decodeTransactionId(teb.getDestinationTransactionId());
            
            // Application Context
            dialogPortion = teb.getDialogPortion();
            
            // Operation Code
            comps = teb.getComponent();

            break;

        case TCAbortMessage._TAG:
            try {
                tub = TcapFactory.createTCAbortMessage(ais);
            } catch (org.mobicents.protocols.ss7.tcap.asn.ParseException e) {
                logger.debug("ParseException when parsing TCAbortMessage: " + e.toString(), e);
                
                firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "TCAP FW: ParseException when parsing TCAbortMessage", lua_hmap);
                return;
            }

            // TID
            dialogId = Utils.decodeTransactionId(tub.getDestinationTransactionId());
            
            // Application Context
            dialogPortion = tub.getDialogPortion();

            break;

        case TCUniMessage._TAG:
            try {
                tcuni = TcapFactory.createTCUniMessage(ais);
            } catch (org.mobicents.protocols.ss7.tcap.asn.ParseException e) {
                logger.debug("ParseException when parsing TCUniMessage: " + e.toString(), e);
                
                firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "TCAP FW: ParseException when parsing TCUniMessage", lua_hmap);
                return;
            }
            
            // Application Context
            dialogPortion = tcuni.getDialogPortion();
            
            // Operation Code
            comps = tcuni.getComponent();

            break;

        default:
            //unrecognizedPackageType(message, localAddress, remoteAddress, ais, tag, message.getNetworkId());
            break;
        }


        // Application Context
        if (dialogPortion != null) {
            // this should not be null....
            DialogAPDU apdu = dialogPortion.getDialogAPDU();
            if (apdu.getType() == DialogAPDUType.Response) {
               DialogResponseAPDU responseAPDU = (DialogResponseAPDU) apdu;
               ACN = responseAPDU.getApplicationContextName();
            } else if (apdu.getType() == DialogAPDUType.Request) {
               DialogRequestAPDU requestAPDU = (DialogRequestAPDU) apdu;
               ACN = requestAPDU.getApplicationContextName();
            }
            
            if (ACN != null) {
                 lua_hmap.put("tcap_ac", ((ApplicationContextNameImpl)ACN).getStringValue());
            }
        }

        // ---------- TCAP firewall ----------
        // TCAP components
        if (comps != null) {
            for (Component comp : comps) {
                if (comp == null) {
                    continue;
                }
                
                OperationCodeImpl oc;
                
                switch (comp.getType()) {
                case Invoke:
                    Invoke inv = (Invoke) comp;

                    // Operation Code
                    oc = (OperationCodeImpl) inv.getOperationCode();
                    
                    // Encryption Autodiscovery Sending Result
                    // Only targeting HPLMN
                    if (oc.getLocalOperationCode() == OC_AUTO_ENCRYPTION
                        && SS7FirewallConfig.encryption_autodiscovery.equals("true")
                        && SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.hplmn_gt, message.getCalledPartyAddress().getGlobalTitle().getDigits())
                        && !SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.hplmn_gt, message.getCallingPartyAddress().getGlobalTitle().getDigits())) {

                        KeyPair myKeyPair = SS7FirewallConfig.simpleWildcardFind(SS7FirewallConfig.called_gt_decryption, message.getCalledPartyAddress().getGlobalTitle().getDigits());
                        String key = SS7FirewallConfig.simpleWildcardKeyFind(SS7FirewallConfig.called_gt_decryption, message.getCalledPartyAddress().getGlobalTitle().getDigits());
                        if (myKeyPair != null) {


                            TCEndMessage t = TcapFactory.createTCEndMessage();

                            
                            t.setDestinationTransactionId(Utils.encodeTransactionId(dialogId));
                            // Create Dialog Portion
                            DialogPortion dp = TcapFactory.createDialogPortion();

                            dp.setOid(true);
                            dp.setOidValue(new long[] { 0, 0, 17, 773, 1, 1, 1 });

                            dp.setAsn(true);

                            DialogRequestAPDUImpl diRequestAPDUImpl = new DialogRequestAPDUImpl();

                            diRequestAPDUImpl.setApplicationContextName(ACN);
                            diRequestAPDUImpl.setDoNotSendProtocolVersion(true);


                            dp.setDialogAPDU(diRequestAPDUImpl);

                            t.setDialogPortion(dp);



                            Component[] c = new Component[1];

                            c[0] = new ReturnResultLastImpl();
                            ((ReturnResultLastImpl)c[0]).setInvokeId(1l);
                            
                            oc.setLocalOperationCode(oc.getLocalOperationCode());
                            ((ReturnResultLastImpl)c[0]).setOperationCode(oc);

                                                        
                            // Reserved (currently not used) - Version
                            // TODO
                            Parameter p1 = TcapFactory.createParameter();
                            p1.setTagClass(Tag.CLASS_PRIVATE);
                            p1.setPrimitive(true);
                            p1.setTag(Tag.STRING_OCTET);
                            p1.setData("v1".getBytes());
                            
                            // GT prefix
                            Parameter p2 = TcapFactory.createParameter();
                            p2.setTagClass(Tag.CLASS_PRIVATE);
                            p2.setPrimitive(true);
                            p2.setTag(Tag.STRING_OCTET);
                            byte[] d2 = key.getBytes();
                            p2.setData(d2);
                            
                            // Public key
                            Parameter p3 = TcapFactory.createParameter();
                            p3.setTagClass(Tag.CLASS_PRIVATE);
                            p3.setPrimitive(true);
                            p3.setTag(Tag.STRING_OCTET);
                            byte[] d3 = myKeyPair.getPublic().getEncoded();
                            p3.setData(d3);
                            
                            Parameter p = TcapFactory.createParameter();
                            p.setTagClass(Tag.CLASS_UNIVERSAL);
                            p.setTag(0x04);
                            p.setParameters(new Parameter[] { p1, p2, p3});
                            ((ReturnResultLastImpl)c[0]).setParameter(p);

                           

                            t.setComponent(c);
                            AsnOutputStream aos = new AsnOutputStream();
                            try {
                                t.encode(aos);
                            } catch (EncodeException ex) {
                                java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                            }

                            byte[] _d = aos.toByteArray();

                            LongMessageRuleType l = lmrt;
                            SccpDataMessage m = this.sccpMessageFactory.createDataMessageClass0(message.getCallingPartyAddress(), message.getCalledPartyAddress(), message.getData(), message.getOriginLocalSsn(), false, null, null);
                            m.setData(_d);

                            logger.info("============ Encryption Autodiscovery Sending Result ============ ");
                
                            // Use XUDT if required
                            if (m.getData().length >= 240) {
                                l = LongMessageRuleType.XUDT_ENABLED;
                            }
                            sendSccpMessage(mupReturn, dpc, opc, sls, ni, l, m);
                            return;
                        }
                        
                    }

                    // TCAP Cat1 filtering
                    if (oc != null) {
                        //logger.debug("TCAP OC = " + oc.getStringValue());
                        lua_hmap.put("tcap_oc", oc.getStringValue());

                        if(SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.tcap_oc_blacklist, oc.getStringValue())) {
                            //logger.info("============ TCAP Blocked Operation Code = " + oc.getStringValue() + " ============");
                            firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "TCAP FW (Cat1): OC = " + oc.getStringValue(), lua_hmap);
                            return;
                        }
                    }
                    
                    // Drop if ACN null for TCAP Begin
                    if (tag == TCBeginMessage._TAG && ACN == null) {
                        firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "TCAP FW (Cat1): Missing AC", lua_hmap);
                        return;
                    }

                    // ---------- MAP decoding ----------
                    String imsi = null;
                                    
                    if (oc != null 
                            && message.getCalledPartyAddress() != null && message.getCalledPartyAddress().getGlobalTitle() != null && message.getCalledPartyAddress().getGlobalTitle().getDigits() != null
                            && message.getCallingPartyAddress() != null && message.getCallingPartyAddress().getGlobalTitle() != null && message.getCallingPartyAddress().getGlobalTitle().getDigits() != null) {
                        // Optimization, decode MAP only if towards HPLMN and not originated from HPLMN
                        if (SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.hplmn_gt, message.getCalledPartyAddress().getGlobalTitle().getDigits())
                            && !SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.hplmn_gt, message.getCallingPartyAddress().getGlobalTitle().getDigits())) {

                            Parameter parameter = inv.getParameter();
                            if (parameter != null) {
                                byte[] buf = parameter.getData();
                                AsnInputStream map_ais = new AsnInputStream(buf);

                                // cancelLocation
                                if (oc.getStringValue().equals("3")) {
                                    CancelLocationRequestImpl ind = new CancelLocationRequestImpl(MAPApplicationContext.getProtocolVersion(ACN.getOid()));
                                    try {
                                        ind.decodeData(map_ais, buf.length);
                                    } catch (MAPParsingComponentException ex) {
                                        //java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                                        firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "MAP FW: Failed decoding, OC = " + oc.getStringValue(), lua_hmap);
                                        return;
                                    }
                                    ind.setInvokeId(inv.getInvokeId());

                                    if (((CancelLocationRequestImpl)ind).getImsi() != null) {
                                        imsi = ((CancelLocationRequestImpl)ind).getImsi().getData();
                                        logger.debug("MAP CL IMSI = " + imsi);
                                        lua_hmap.put("map_imsi", imsi);
                                    }
                                }
                                // provideRoamingNumber
                                if (oc.getStringValue().equals("4")) {
                                    ProvideRoamingNumberRequestImpl ind = new ProvideRoamingNumberRequestImpl(MAPApplicationContext.getProtocolVersion(ACN.getOid()));
                                    try {
                                        ind.decodeData(map_ais, buf.length);
                                    } catch (MAPParsingComponentException ex) {
                                        //java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                                        firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "MAP FW: Failed decoding, OC = " + oc.getStringValue(), lua_hmap);
                                        return;
                                    }
                                    ind.setInvokeId(inv.getInvokeId());

                                    if (((ProvideRoamingNumberRequestImpl)ind).getImsi() != null) {
                                        imsi = ((ProvideRoamingNumberRequestImpl)ind).getImsi().getData();
                                        logger.debug("MAP PRN IMSI = " + imsi);
                                        lua_hmap.put("map_imsi", imsi);
                                    }
                                }
                                // insertSubscriberData
                                if (oc.getStringValue().equals("7")) {
                                    InsertSubscriberDataRequestImpl ind = new InsertSubscriberDataRequestImpl(MAPApplicationContext.getProtocolVersion(ACN.getOid()));
                                    try {
                                        ind.decodeData(map_ais, buf.length);
                                    } catch (MAPParsingComponentException ex) {
                                        //java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                                        firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "MAP FW: Failed decoding, OC = " + oc.getStringValue(), lua_hmap);
                                        return;
                                    }
                                    ind.setInvokeId(inv.getInvokeId());

                                    if (((InsertSubscriberDataRequestImpl)ind).getImsi() != null) {
                                        imsi = ((InsertSubscriberDataRequestImpl)ind).getImsi().getData();
                                        logger.debug("MAP ISD IMSI = " + imsi);
                                        lua_hmap.put("map_imsi", imsi);
                                    }
                                }
                                // deleteSubscriberData
                                if (oc.getStringValue().equals("8")) {
                                    DeleteSubscriberDataRequestImpl ind = new DeleteSubscriberDataRequestImpl();
                                    try {
                                        ind.decodeData(map_ais, buf.length);
                                    } catch (MAPParsingComponentException ex) {
                                        //java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                                        firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "MAP FW: Failed decoding, OC = " + oc.getStringValue(), lua_hmap);
                                        return;
                                    }
                                    ind.setInvokeId(inv.getInvokeId());

                                    if (((DeleteSubscriberDataRequestImpl)ind).getImsi() != null) {
                                        imsi = ((DeleteSubscriberDataRequestImpl)ind).getImsi().getData();
                                        logger.debug("MAP DSD IMSI = " + imsi);
                                        lua_hmap.put("map_imsi", imsi);
                                    }
                                }
                                // provideSubscriberInfo
                                if (oc.getStringValue().equals("70")) {
                                    ProvideSubscriberInfoRequestImpl ind = new ProvideSubscriberInfoRequestImpl();
                                    try {
                                        ind.decodeData(map_ais, buf.length);
                                    } catch (MAPParsingComponentException ex) {
                                        //java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                                        firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "MAP FW: Failed decoding, OC = " + oc.getStringValue(), lua_hmap);
                                        return;
                                    }
                                    ind.setInvokeId(inv.getInvokeId());

                                    if (((ProvideSubscriberInfoRequestImpl)ind).getImsi() != null) {
                                        imsi = ((ProvideSubscriberInfoRequestImpl)ind).getImsi().getData();
                                        logger.debug("MAP PSI IMSI = " + imsi);
                                        lua_hmap.put("map_imsi", imsi);
                                    }
                                }
                            }
                        }
                    }
                    // ----------------------------------
                    
                    // ---------- MAP firewall ----------
                    // MAP Cat2 filtering
                    if (oc != null && tag == TCBeginMessage._TAG) {
                        if (SS7FirewallConfig.map_cat2_oc_blacklist.containsKey(oc.getStringValue())) {
                            // If towards HPLMN and not originated from HPLMN
                            if (SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.hplmn_gt, message.getCalledPartyAddress().getGlobalTitle().getDigits())
                                    && !SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.hplmn_gt, message.getCallingPartyAddress().getGlobalTitle().getDigits())) {

                                // Drop if message targets IMSI in HPLMN
                                if (imsi != null) {
                                    // IMSI prefix check
                                    for (String imsi_prefix: SS7FirewallConfig.hplmn_imsi.keySet()) {
                                        if (imsi.startsWith(imsi_prefix)) {
                                            // logger.info("============ MAP Cat2 Blocked Operation Code = " + oc.getStringValue() + " ============");
                                            firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "MAP FW (Cat2): OC = " + oc.getStringValue(), lua_hmap);
                                            return;
                                        }
                                    }
                                }
                            }

                        }
                    }
                    // ----------------------------------
                    break;
                case ReturnResult:
                    break;
                case ReturnResultLast:
                    ReturnResultLast result = (ReturnResultLast) comp;
                    
                    // Operation Code
                    oc = (OperationCodeImpl) result.getOperationCode();
                    
                    // Encryption Autodiscovery Receiving Result
                    // Only targeting HPLMN
                    
                    if (oc.getLocalOperationCode() == OC_AUTO_ENCRYPTION
                        && SS7FirewallConfig.encryption_autodiscovery.equals("true")
                        && message.getCalledPartyAddress() != null && message.getCalledPartyAddress().getGlobalTitle() != null && message.getCalledPartyAddress().getGlobalTitle().getDigits() != null
                        && SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.hplmn_gt, message.getCalledPartyAddress().getGlobalTitle().getDigits())
                        && message.getCallingPartyAddress() != null && message.getCallingPartyAddress().getGlobalTitle() != null && message.getCallingPartyAddress().getGlobalTitle().getDigits() != null
                        && !SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.hplmn_gt, message.getCallingPartyAddress().getGlobalTitle().getDigits())) {

                        logger.info("============ Encryption Autodiscovery Receiving Result ============ ");
                        
                        if (encryption_autodiscovery_sessions.containsKey(message.getCallingPartyAddress().getGlobalTitle().getDigits().substring(0, Math.min(encryption_autodiscovery_digits, message.getCallingPartyAddress().getGlobalTitle().getDigits().length())))
                            && encryption_autodiscovery_sessions.get(message.getCallingPartyAddress().getGlobalTitle().getDigits().substring(0, Math.min(encryption_autodiscovery_digits, message.getCallingPartyAddress().getGlobalTitle().getDigits().length()))) == dialogId) {

                            // do not remove the key and wait for expiration to not send too many autodiscovery request messages
                            //encryption_autodiscovery_sessions.remove(message.getCallingPartyAddress().getGlobalTitle().getDigits().substring(0, Math.min(encryption_autodiscovery_digits, message.getCallingPartyAddress().getGlobalTitle().getDigits().length())));                          
                            
                            Parameter p = result.getParameter();
                            Parameter[] params = p.getParameters();
                            if (params != null && params.length >= 2) {
                                
                                // Reserved (currently not used) - Public key type
                                // TODO
                                Parameter p1 = params[0];
                                
                                // GT prefix
                                Parameter p2 = params[1];
                                byte[] d2 = p2.getData();
                                String called_gt = new String(d2);

                                // Public key
                                Parameter p3 = params[2];
                                byte[] d3 = p3.getData();
                                // TODO add method into config to add public key
                                byte[] publicKeyBytes =  d3;
                                try {
                                    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                                    PublicKey publicKey;
                                    publicKey = keyFactory.generatePublic(pubKeySpec);
                                    SS7FirewallConfig.called_gt_encryption.put(called_gt, publicKey);
                                } catch (InvalidKeySpecException ex) {
                                    java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                                }
                                
                            }
                            
                        }
                        
                        // do not forward message
                        return;
                    }      
                    
                    
                    
                    break;
                case ReturnError:
                    ReturnError re = (ReturnError) comp;
                    ErrorCodeImpl ec = (ErrorCodeImpl) re.getErrorCode();
                    if (ec != null) {
                    }
                    break;
                case Reject:
                    Reject rej = (Reject) comp;
                    if (!rej.isLocalOriginated()) {
                        ProblemImpl prob = (ProblemImpl) rej.getProblem();
                        if (prob != null) {
                        }
                    }
                    break;
                }
            }
        }
        
        // -------------- LUA rules -----------------
        ScriptEngineManager mgr = new ScriptEngineManager();
	ScriptEngine eng = mgr.getEngineByName("luaj");
        for (String key : lua_hmap.keySet()) {
            eng.put(key, lua_hmap.get(key));
        }

        boolean lua_match = false;
        int i;
        for (i = 0; i < SS7FirewallConfig.lua_blacklist_rules.size(); i++) {
            try {
                eng.eval("y = " + (String)SS7FirewallConfig.lua_blacklist_rules.get(i));
                boolean r =  Boolean.valueOf(eng.get("y").toString());
                lua_match |= r;
                if (r) {
                    //logger.debug("============ LUA rules blacklist: " + SS7FirewallConfig.lua_blacklist_rules.get(i) + " ============");
                    //logger.debug("============ LUA variables ============");
                    //for (String key : lua_hmap.keySet()) {
                    //    logger.debug(key + ": " + lua_hmap.get(key));
                    //}
                    break;
                }
            } catch (ScriptException ex) {
                java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        if (lua_match) {
            firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "MAP FW:  Match with Lua rule " + i, lua_hmap);
            return;
        }
        // ------------------------------------------
        
        // ------------- IDS API rules ---------------
        if (connectorIDS != null) {
            EncodingResultData erd;
            try {
                erd = ((SccpMessageImpl)message).encode(this.sccpStack, lmrt, mup.getMaxUserDataLength(dpc), logger, this.sccpStack.isRemoveSpc(),
                        this.sccpStack.getSccpProtocolVersion());
                if(connectorIDS.evalSCCPMessage(DatatypeConverter.printHexBinary(erd.getSolidData())) == false) {
                    firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "MAP FW:  Blocked by IDS", lua_hmap);
                    return;
                }
            } catch (ParseException ex) {
                java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        // ------------------------------------------
        
        // --------------- TCAP signing ---------------
        if (tag == TCBeginMessage._TAG) {
            lmrt = tcapSign(message, tcb, comps, lmrt);
        }
        // --------------------------------------------
        
        // ------------ TCAP encryption -------------
        if (message.getCalledPartyAddress() != null) { 
            if (message.getCalledPartyAddress().getGlobalTitle() != null) {
                PublicKey publicKey = SS7FirewallConfig.simpleWildcardFind(SS7FirewallConfig.called_gt_encryption, message.getCalledPartyAddress().getGlobalTitle().getDigits());
                if (publicKey != null) {
                    logger.debug("TCAP Encryption for SCCP Called GT = " + message.getCalledPartyAddress().getGlobalTitle().getDigits());
                
                    try {
                        // Sending XUDT message from UDT message
                        
                        // SPI(version) and TVP(timestamp)
                        byte[] SPI = {0x00, 0x00, 0x00, 0x00};  // TODO
                        byte[] TVP = {0x00, 0x00, 0x00, 0x00};
                        
                        long t = System.currentTimeMillis()/100;    // in 0.1s
                        TVP[0] = (byte) ((t >> 24) & 0xFF);
                        TVP[1] = (byte) ((t >> 16) & 0xFF);
                        TVP[2] = (byte) ((t >>  8) & 0xFF);
                        TVP[3] = (byte) ((t >>  0) & 0xFF);
                        
                        RSAPublicKey rsaPublicKey = (RSAPublicKey)publicKey;
                        SS7FirewallConfig.cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                        
                        int keyLength = rsaPublicKey.getModulus().bitLength() / 8;
                        
                        byte[][] datas = splitByteArray(message.getData(), keyLength - 11 - 4);
                        byte[] cipherText = null;
                        for (byte[] b : datas) {
                            cipherText = concatByteArray(cipherText, SS7FirewallConfig.cipher.doFinal(concatByteArray(TVP, b)));
                        }
                        
                        cipherText = concatByteArray(SPI, cipherText);
                        
                        SccpDataMessage m = this.sccpMessageFactory.createDataMessageClass0(message.getCalledPartyAddress(), message.getCallingPartyAddress(), cipherText, message.getOriginLocalSsn(), false, null, null);
                        message = m;
                        lmrt = LongMessageRuleType.XUDT_ENABLED;
                    } catch (InvalidKeyException ex) {
                        java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IllegalBlockSizeException ex) {
                        java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (BadPaddingException ex) {
                        java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
                // ------------ Encryption Autodiscovery ------------ 
                // only if not towards HPLMN
                else if (SS7FirewallConfig.encryption_autodiscovery.equals("true")
                        && tag == TCBeginMessage._TAG
                        && !SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.hplmn_gt, message.getCalledPartyAddress().getGlobalTitle().getDigits())
                        && SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.hplmn_gt, message.getCallingPartyAddress().getGlobalTitle().getDigits())) {
                    
                    if (!encryption_autodiscovery_sessions.containsKey(message.getCalledPartyAddress().getGlobalTitle().getDigits().substring(0, Math.min(encryption_autodiscovery_digits, message.getCallingPartyAddress().getGlobalTitle().getDigits().length())))) {
                        logger.debug("============ Preparing Autodiscovery Invoke ============ ");

                        TCBeginMessage t = TcapFactory.createTCBeginMessage();


                        byte[] otid = { (byte)randomGenerator.nextInt(256), (byte)randomGenerator.nextInt(256), (byte)randomGenerator.nextInt(256), (byte)randomGenerator.nextInt(256) };
                        t.setOriginatingTransactionId(otid);
                        // Create Dialog Portion
                        DialogPortion dp = TcapFactory.createDialogPortion();

                        dp.setOid(true);
                        dp.setOidValue(new long[] { 0, 0, 17, 773, 1, 1, 1 });

                        dp.setAsn(true);

                        DialogRequestAPDUImpl diRequestAPDUImpl = new DialogRequestAPDUImpl();

                        // TODO change Application Context
                        ApplicationContextNameImpl acn = new ApplicationContextNameImpl();
                        acn.setOid(new long[] { 0, 4, 0, 0, 1, 0, 19, 2 });

                        diRequestAPDUImpl.setApplicationContextName(acn);
                        diRequestAPDUImpl.setDoNotSendProtocolVersion(true);

                        dp.setDialogAPDU(diRequestAPDUImpl);

                        t.setDialogPortion(dp);

                        Component[] c = new Component[1];

                        c[0] = new InvokeImpl();
                        ((InvokeImpl)c[0]).setInvokeId(1l);
                        OperationCode oc = TcapFactory.createOperationCode();
                        oc.setLocalOperationCode(OC_AUTO_ENCRYPTION);
                        ((InvokeImpl)c[0]).setOperationCode(oc);


                        t.setComponent(c);
                        AsnOutputStream aos = new AsnOutputStream();
                        try {
                            t.encode(aos);
                        } catch (EncodeException ex) {
                            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                        }

                        byte[] _d = aos.toByteArray();
                        
                        LongMessageRuleType l = lmrt;
                        SccpDataMessage m = this.sccpMessageFactory.createDataMessageClass0(message.getCalledPartyAddress(), message.getCallingPartyAddress(), message.getData(), message.getOriginLocalSsn(), false, null, null);
                        m.setData(_d);

                        // --------- Add also TCAP signature ------------
                        lmrt = tcapSign(m, t, c, lmrt);
                        // ----------------------------------------------
                        
                        logger.info("============ Sending Autodiscovery Invoke ============ ");
                        
                        // Use XUDT if required
                        if (m.getData().length >= 240) {
                            l = LongMessageRuleType.XUDT_ENABLED;
                        }
                        sendSccpMessage(mup, opc, dpc, sls, ni, l, m);
                        encryption_autodiscovery_sessions.put(message.getCalledPartyAddress().getGlobalTitle().getDigits().substring(0, Math.min(encryption_autodiscovery_digits, message.getCallingPartyAddress().getGlobalTitle().getDigits().length())), Utils.decodeTransactionId(otid));

                    }
                    // ---------- Encryption Autodiscovery End ---------- 
                }
            }
        }
        // ------------------------------------------
        
        logger.debug("============ Forwarding Message ============ ");
        // Use XUDT if required
        if (message.getData().length >= 240) {
            lmrt = LongMessageRuleType.XUDT_ENABLED;
            SccpDataMessage m = this.sccpMessageFactory.createDataMessageClass0(message.getCalledPartyAddress(), message.getCallingPartyAddress(), message.getData(), message.getOriginLocalSsn(), false, null, null);
            message = m;
        }
        sendSccpMessage(mup, opc, dpc, sls, ni, lmrt, message);
        
    }
    
    /**
     * Main function to start the SS7 Firewall.
     * 
     * @param args
     */
    public static void main(String[] args) {
        logger.debug("*************************************");
        logger.debug("***           SS7Firewall         ***");
        logger.debug("*************************************");
        
        /*
        // TODO remove this code, used only for LUA testing
        ScriptEngineManager mgr = new ScriptEngineManager();
	ScriptEngine eng = mgr.getEngineByName("luaj");
	eng.put("sccp_calling_gt", 20);
        eng.put("tcap_oc", 0);
        try {
            eng.eval("y = sccp_calling_gt == 20 and tcap_oc == 0");
            System.out.println( "y=" + eng.get("y") );
        } catch (ScriptException ex) {
            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }*/  
        
        // clear XML dir
        File index = new File(persistDir);
        if (!index.exists()) {
            index.mkdir();
        } else {
            String[]entries = index.list();
            for(String s: entries){
                File currentFile = new File(index.getPath(),s);
                currentFile.delete();
            }
        }
        //
        if (args.length >= 1) {
            configName = args[0];
        }

        
        try {
            // Use last config
            SS7FirewallConfig.loadConfigFromFile(configName + ".last");
            // TODO use the following directive instead to do not use .last configs
            //SS7FirewallConfig.loadConfigFromFile(configName);
        } catch (Exception ex) {
            try {
                SS7FirewallConfig.loadConfigFromFile(configName);
            } catch (IOException ex1) {
                java.util.logging.Logger.getLogger(SS7FirewallConfig.class.getName()).log(Level.SEVERE, null, ex1);
            } catch (org.json.simple.parser.ParseException ex1) {
                java.util.logging.Logger.getLogger(SS7FirewallConfig.class.getName()).log(Level.SEVERE, null, ex1);
            }
        }
        
        logger.setLevel(org.apache.log4j.Level.DEBUG);
        
        // ---- REST API -----
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        
        jettyServer = new Server();
        
        HttpConfiguration http_config = new HttpConfiguration();
        http_config.setSecureScheme("https");
        http_config.setSecurePort(8443);
        http_config.setOutputBufferSize(32768);
        /*ServerConnector http = new ServerConnector(jettyServer,
                new HttpConnectionFactory(http_config));
        http.setPort(8080);
        http.setIdleTimeout(30000);*/

        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setIncludeCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        sslContextFactory.setIncludeProtocols("TLSv1.2");
        sslContextFactory.setKeyStorePath("ss7fw_keystore");
        sslContextFactory.setKeyStorePassword("BkgcNSrVn4wQWNpEowoHeHxgZeSn5WV7");
        sslContextFactory.setKeyManagerPassword("BkgcNSrVn4wQWNpEowoHeHxgZeSn5WV7");
        
        
        HttpConfiguration https_config = new HttpConfiguration(http_config);
        SecureRequestCustomizer src = new SecureRequestCustomizer();
        src.setStsMaxAge(2000);
        src.setStsIncludeSubDomains(true);
        https_config.addCustomizer(src);

        ServerConnector https = new ServerConnector(jettyServer,
            new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                new HttpConnectionFactory(https_config));
        https.setPort(8443);
        https.setIdleTimeout(500000);

        //jettyServer.setConnectors(new Connector[] { http, https });
        jettyServer.setConnectors(new Connector[] { https });
        
        
        
        // ------- Basic Auth ---------
        
        LoginService loginService = new HashLoginService("ss7fw",
                "realm.properties");
        jettyServer.addBean(loginService);

        ConstraintSecurityHandler security = new ConstraintSecurityHandler();
        jettyServer.setHandler(security);

        Constraint constraint = new Constraint();
        constraint.setName("auth");
        constraint.setAuthenticate(true);
        constraint.setRoles(new String[] { "user", "admin" });

        ConstraintMapping mapping = new ConstraintMapping();
        mapping.setPathSpec("/*");
        mapping.setConstraint(constraint);

        security.setConstraintMappings(Collections.singletonList(mapping));
        security.setAuthenticator(new BasicAuthenticator());
        security.setLoginService(loginService);

        security.setHandler(context);
        // --------------------------       
        
        //jettyServer.setHandler(context);

        ServletHolder jerseyServlet = context.addServlet(
             org.glassfish.jersey.servlet.ServletContainer.class, "/*");
        jerseyServlet.setInitOrder(0);

        // Tells the Jersey Servlet which REST service/class to load.
        jerseyServlet.setInitParameter(
           "jersey.config.server.provider.classnames",
           SS7FirewallAPI_V1_0.class.getCanonicalName());
        
        
        try {
            jettyServer.start();
            //jettyServer.join();
        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            //jettyServer.destroy();
        }
        // ------------------
        
        // ---- IDS API -----
        try {
            String ids_api_type = (String)SS7FirewallConfig.get("$.sigfw_configuration.firewall_rules.ids.ids_api_type");
            if(ids_api_type != null && ids_api_type.equals("REST")) {
                connectorIDS = new ConnectorIDS();
                connectorIDS.initialize(ConnectorIDSModuleRest.class);

                List<Map<String, Object>> ids_servers = SS7FirewallConfig.get("$.sigfw_configuration.firewall_rules.ids.ids_servers");
                for (int i = 0; i < ids_servers.size(); i++) {
                    //connectorIDS.addServer("https://localhost:8443", "user", "password");
                    connectorIDS.addServer(
                            (String)ids_servers.get(i).get("host"),
                            (String)ids_servers.get(i).get("username"),
                            (String)ids_servers.get(i).get("password")
                    );

                    // TODO remove this code, used only for to test REST API
                    // System.out.println("--------------------------");
                    // System.out.println(connectorIDS.evalSCCPMessage("test"));
                    // System.out.println("--------------------------");
                    // ------------------
                }
            }
        } catch (Exception e) {
            // None
        }
        
        // ---- mThreat API -----
        try {
            String mthreat_api_type = (String)SS7FirewallConfig.get("$.sigfw_configuration.firewall_rules.mthreat.mthreat_api_type");
            if(mthreat_api_type != null && mthreat_api_type.equals("REST")) {
                connectorMThreat = new ConnectorMThreat();
                connectorMThreat.initialize(ConnectorMThreatModuleRest.class, mThreat_alerts);

                List<Map<String, Object>> ids_servers = SS7FirewallConfig.get("$.sigfw_configuration.firewall_rules.mthreat.mthreat_servers");
                for (int i = 0; i < ids_servers.size(); i++) {
                    //connectorIDS.addServer("https://localhost:8443", "user", "password");
                    connectorMThreat.addServer(
                            (String)ids_servers.get(i).get("host"),
                            (String)ids_servers.get(i).get("username"),
                            (String)ids_servers.get(i).get("password")
                    );
                }
            }
        } catch (Exception e) {
            // None
        }
        
        IpChannelType ipChannelType = IpChannelType.SCTP;
        if (args.length >= 2 && args[1].toLowerCase().equals("tcp")) {
            ipChannelType = IpChannelType.TCP;
        }

        final SS7Firewall sigfw = new SS7Firewall();
        try {
            sigfw.initializeStack(ipChannelType);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        int t = 0;
        try {
            while (true) {

                if(sigfw.serverM3UAMgmt.isStarted() == true) {
                   
                } else {
                    sigfw.serverM3UAMgmt.start();
                }
                Thread.sleep(1000);
                
                t++;
                // Save config every 10s
                if (t%10 == 0) {
                    //logger.debug("X");
                    SS7FirewallConfig.saveConfigToFile(configName + ".last");
                }
            }
        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    // ------------------------------------------
    // ------------ Override methods ------------
    // ------------------------------------------
    
    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onMAPMessage(org
	 * .mobicents.protocols.ss7.map.api.MAPMessage)
     */
    @Override
    public void onMAPMessage(MAPMessage msg) {
        logger.debug("[[[[[[[[[[    MAP Message Recieved      ]]]]]]]]]]");
        logger.debug(msg.toString());
        if (msg.getMAPDialog() != null) {
            logger.debug("MAP AC = " + msg.getMAPDialog().getApplicationContext().toString());
        }
        logger.debug("MAP OC = " + msg.getOperationCode());
        
        // Generic MAP messages detection test
        if (msg.getMessageType().equals(MAPMessageType.processUnstructuredSSRequest_Request)) {
            logger.debug("MAP processUnstructuredSSRequest_Request detected");
        } else if (msg.getMessageType().equals(MAPMessageType.anyTimeInterrogation_Request)) {
            logger.debug("MAP anyTimeInterrogation_Request detected");
        }
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see org.mobicents.protocols.ss7.map.api.MAPServiceListener#
	 * onProviderErrorComponent(org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * java.lang.Long,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPProviderError)
     */
    public void onProviderErrorComponent(MAPDialog mapDialog, Long invokeId) {
        logger.error(String.format("onProviderErrorComponent for Dialog=%d and invokeId=%d MAPProviderError=%s",
                mapDialog.getLocalDialogId(), invokeId));
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onRejectComponent
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog, java.lang.Long,
	 * org.mobicents.protocols.ss7.tcap.asn.comp.Problem)
     */
    public void onRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem) {
        logger.error(String.format("onRejectComponent for Dialog=%d and invokeId=%d Problem=%s",
                mapDialog.getLocalDialogId(), invokeId, problem));
    }
    
    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogAccept(
	 * org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogAccept(MAPDialog mapDialog, MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogAccept for DialogId=%d MAPExtensionContainer=%s",
                    mapDialog.getLocalDialogId(), extensionContainer));
        }
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogClose(org
	 * .mobicents.protocols.ss7.map.api.MAPDialog)
     */
    @Override
    public void onDialogClose(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogClose for Dialog=%d", mapDialog.getLocalDialogId()));
        }
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogDelimiter
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog)
     */
    @Override
    public void onDialogDelimiter(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogDelimiter for DialogId=%d", mapDialog.getLocalDialogId()));
        }
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogNotice(
	 * org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic)
     */
    @Override
    public void onDialogNotice(MAPDialog mapDialog, MAPNoticeProblemDiagnostic noticeProblemDiagnostic) {
        logger.error(String.format("onDialogNotice for DialogId=%d MAPNoticeProblemDiagnostic=%s ",
                mapDialog.getLocalDialogId(), noticeProblemDiagnostic));
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogProviderAbort
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPAbortProviderReason,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPAbortSource,
	 * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogProviderAbort(MAPDialog mapDialog, MAPAbortProviderReason abortProviderReason,
            MAPAbortSource abortSource, MAPExtensionContainer extensionContainer) {
        logger.error(String
                .format("onDialogProviderAbort for DialogId=%d MAPAbortProviderReason=%s MAPAbortSource=%s MAPExtensionContainer=%s",
                        mapDialog.getLocalDialogId(), abortProviderReason, abortSource, extensionContainer));
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogReject(
	 * org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPRefuseReason,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPProviderError,
	 * org.mobicents.protocols.ss7.tcap.asn.ApplicationContextName,
	 * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogReject(MAPDialog mapDialog, MAPRefuseReason refuseReason,
            ApplicationContextName alternativeApplicationContext, MAPExtensionContainer extensionContainer) {
        logger.error(String
                .format("onDialogReject for DialogId=%d MAPRefuseReason=%s MAPProviderError=%s ApplicationContextName=%s MAPExtensionContainer=%s",
                        mapDialog.getLocalDialogId(), refuseReason, alternativeApplicationContext,
                        extensionContainer));
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogRelease
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog)
     */
    @Override
    public void onDialogRelease(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogResease for DialogId=%d", mapDialog.getLocalDialogId()));
        }
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogRequest
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * org.mobicents.protocols.ss7.map.api.primitives.AddressString,
	 * org.mobicents.protocols.ss7.map.api.primitives.AddressString,
	 * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogRequest(MAPDialog mapDialog, AddressString destReference, AddressString origReference,
            MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String
                    .format("onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s MAPExtensionContainer=%s",
                            mapDialog.getLocalDialogId(), destReference, origReference, extensionContainer));
        }
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogRequestEricsson
     */
    @Override
    public void onDialogRequestEricsson(MAPDialog mapd, AddressString as, AddressString as1, AddressString as2, AddressString as3) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s ",
                    mapd.getLocalDialogId(), as, as1, as2, as3));
        }
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogTimeout
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog)
     */
    @Override
    public void onDialogTimeout(MAPDialog mapDialog) {
        logger.error(String.format("onDialogTimeout for DialogId=%d", mapDialog.getLocalDialogId()));
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPDialogListener#onDialogUserAbort
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog,
	 * org.mobicents.protocols.ss7.map.api.dialog.MAPUserAbortChoice,
	 * org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogUserAbort(MAPDialog mapDialog, MAPUserAbortChoice userReason,
            MAPExtensionContainer extensionContainer) {
        logger.error(String.format("onDialogUserAbort for DialogId=%d MAPUserAbortChoice=%s MAPExtensionContainer=%s",
                mapDialog.getLocalDialogId(), userReason, extensionContainer));
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onErrorComponent
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog, java.lang.Long,
	 * org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage)
     */
    @Override
    public void onErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage mapErrorMessage) {
        logger.error(String.format("onErrorComponent for Dialog=%d and invokeId=%d MAPErrorMessage=%s",
                mapDialog.getLocalDialogId(), invokeId, mapErrorMessage));
    }

    /*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.mobicents.protocols.ss7.map.api.MAPServiceListener#onInvokeTimeout
	 * (org.mobicents.protocols.ss7.map.api.MAPDialog, java.lang.Long)
     */
    @Override
    public void onInvokeTimeout(MAPDialog mapDialog, Long invokeId) {
        logger.error(String.format("onInvokeTimeout for Dialog=%d and invokeId=%d", mapDialog.getLocalDialogId(), invokeId));
    }

    @Override
    public void onNotice(SccpNoticeMessage message) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.

    }

    public void onCoordRequest(int dpc, int ssn, int multiplicityIndicator) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.

    }

    public void onCoordResponse(int dpc, int ssn, int multiplicityIndicator) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.

    }

    @Override
    public void onState(int dpc, int ssn, boolean inService, int multiplicityIndicator) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.

    }

    public void onPcState(int dpc, SignallingPointStatus status, int restrictedImportanceLevel, RemoteSccpStatus remoteSccpStatus) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.

    }

    /**
     * Method to capture M3UA raw messages. The messages are stored
     * in M3UA FIFO buffer, over API it is possible to read the buffer. 
     * 
     * @param msg M3UA message
     */
    @Override
    public void onMtp3TransferMessage(Mtp3TransferPrimitive msg) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[    onMtp3TransferMessage      ]]]]]]]]]]");
        logger.debug(msg.toString());
        
        // M3UA FIFO
        /*StringBuilder sb = new StringBuilder();
        for (byte b : msg.encodeMtp3()) {
            sb.append(String.format("%02X", b));
        }
        //m3ua_fifo.add("{" + Instant.now().toEpochMilli() + ": " + sb.toString() + "}");
        m3ua_fifo.add("{" + System.currentTimeMillis() + ": " + sb.toString() + "}");
        while (m3ua_fifo.size() > m3ua_fifo_max_size) {
            m3ua_fifo.pop();
        }*/
        
    }

    @Override
    public void onMtp3PauseMessage(Mtp3PausePrimitive msg) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onMtp3PauseMessage      ]]]]]]]]]]");
        logger.debug(msg.toString());
    }

    @Override
    public void onMtp3ResumeMessage(Mtp3ResumePrimitive msg) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onMtp3ResumeMessage      ]]]]]]]]]]");
        logger.debug(msg.toString());
    }

    @Override
    public void onMtp3StatusMessage(Mtp3StatusPrimitive msg) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onMtp3StatusMessage      ]]]]]]]]]]");
        logger.debug(msg.toString());
    }

    @Override
    public void onTCUni(TCUniIndication ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onTCUni      ]]]]]]]]]]");
    }

    @Override
    public void onTCBegin(TCBeginIndication ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onTCBegin      ]]]]]]]]]]");
    }

    @Override
    public void onTCContinue(TCContinueIndication ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onTCContinue      ]]]]]]]]]]");
    }

    @Override
    public void onTCEnd(TCEndIndication ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onTCEnd      ]]]]]]]]]]");
    }

    @Override
    public void onTCUserAbort(TCUserAbortIndication ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onTCUserAbort      ]]]]]]]]]]");
    }

    @Override
    public void onTCPAbort(TCPAbortIndication ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onTCPAbort      ]]]]]]]]]]");
    }

    @Override
    public void onTCNotice(TCNoticeIndication ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onTCNotice      ]]]]]]]]]]");
    }

    @Override
    public void onDialogReleased(Dialog d) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onDialogReleased      ]]]]]]]]]]");
    }

    @Override
    public void onInvokeTimeout(Invoke tcInvokeRequest) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onInvokeTimeout      ]]]]]]]]]]");
    }

    @Override
    public void onDialogTimeout(Dialog d) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onDialogTimeout      ]]]]]]]]]]");
    }
    
    @Override
    public void onRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem, boolean isLocalOriginated) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onRejectComponentt      ]]]]]]]]]]");
    }
    
    @Override
    public void onProcessUnstructuredSSRequest(ProcessUnstructuredSSRequest procUnstrReqInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onProcessUnstructuredSSRequest      ]]]]]]]]]]");
    }

    @Override
    public void onProcessUnstructuredSSResponse(ProcessUnstructuredSSResponse procUnstrResInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onProcessUnstructuredSSResponse      ]]]]]]]]]]");
    }

    @Override
    public void onUnstructuredSSNotifyRequest(UnstructuredSSNotifyRequest unstrNotifyInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onUnstructuredSSNotifyRequest      ]]]]]]]]]]");
    }

    @Override
    public void onUnstructuredSSNotifyResponse(UnstructuredSSNotifyResponse unstrNotifyInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onUnstructuredSSNotifyResponse      ]]]]]]]]]]");
    }

    @Override
    public void onUnstructuredSSRequest(UnstructuredSSRequest unstrReqInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   UnstructuredSSRequest      ]]]]]]]]]]");
    }

    @Override
    public void onUnstructuredSSResponse(UnstructuredSSResponse unstrResInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onUnstructuredSSResponse      ]]]]]]]]]]");
    }

    @Override
    public void onUpdateLocationRequest(UpdateLocationRequest ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onUpdateLocationRequest      ]]]]]]]]]]");
    }

    @Override
    public void onUpdateLocationResponse(UpdateLocationResponse ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onUpdateLocationResponse      ]]]]]]]]]]");
    }

    @Override
    public void onCancelLocationRequest(CancelLocationRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onCancelLocationRequest      ]]]]]]]]]]");
    }

    @Override
    public void onCancelLocationResponse(CancelLocationResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onCancelLocationResponse      ]]]]]]]]]]");
    }

    @Override
    public void onSendIdentificationRequest(SendIdentificationRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSendIdentificationRequest      ]]]]]]]]]]");
    }

    @Override
    public void onSendIdentificationResponse(SendIdentificationResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSendIdentificationResponse      ]]]]]]]]]]");
    }

    @Override
    public void onUpdateGprsLocationRequest(UpdateGprsLocationRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onUpdateGprsLocationRequest      ]]]]]]]]]]");
    }

    @Override
    public void onUpdateGprsLocationResponse(UpdateGprsLocationResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onUpdateGprsLocationResponse      ]]]]]]]]]]");
    }

    @Override
    public void onPurgeMSRequest(PurgeMSRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onPurgeMSRequest      ]]]]]]]]]]");
    }

    @Override
    public void onPurgeMSResponse(PurgeMSResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onPurgeMSResponse      ]]]]]]]]]]");
    }

    @Override
    public void onSendAuthenticationInfoRequest(SendAuthenticationInfoRequest ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSendAuthenticationInfoRequest      ]]]]]]]]]]");
    }

    @Override
    public void onSendAuthenticationInfoResponse(SendAuthenticationInfoResponse ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSendAuthenticationInfoResponse      ]]]]]]]]]]");
    }

    @Override
    public void onAuthenticationFailureReportRequest(AuthenticationFailureReportRequest ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onAuthenticationFailureReportRequest      ]]]]]]]]]]");
    }

    @Override
    public void onAuthenticationFailureReportResponse(AuthenticationFailureReportResponse ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onAuthenticationFailureReportResponse      ]]]]]]]]]]");
    }

    @Override
    public void onResetRequest(ResetRequest ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onResetRequest      ]]]]]]]]]]");
    }

    @Override
    public void onForwardCheckSSIndicationRequest(ForwardCheckSSIndicationRequest ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onForwardCheckSSIndicationRequest      ]]]]]]]]]]");
    }

    @Override
    public void onRestoreDataRequest(RestoreDataRequest ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onRestoreDataRequest      ]]]]]]]]]]");
    }

    @Override
    public void onRestoreDataResponse(RestoreDataResponse ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onRestoreDataResponse      ]]]]]]]]]]");
    }

    @Override
    public void onAnyTimeInterrogationRequest(AnyTimeInterrogationRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onAnyTimeInterrogationRequest      ]]]]]]]]]]");
        
    }

    @Override
    public void onAnyTimeInterrogationResponse(AnyTimeInterrogationResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onAnyTimeInterrogationResponse      ]]]]]]]]]]");
    }

    @Override
    public void onProvideSubscriberInfoRequest(ProvideSubscriberInfoRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onProvideSubscriberInfoRequest      ]]]]]]]]]]");
    }

    @Override
    public void onProvideSubscriberInfoResponse(ProvideSubscriberInfoResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onProvideSubscriberInfoResponse      ]]]]]]]]]]");
    }

    @Override
    public void onInsertSubscriberDataRequest(InsertSubscriberDataRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onInsertSubscriberDataRequest      ]]]]]]]]]]");
    }

    @Override
    public void onInsertSubscriberDataResponse(InsertSubscriberDataResponse request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onInsertSubscriberDataResponse      ]]]]]]]]]]");
    }

    @Override
    public void onDeleteSubscriberDataRequest(DeleteSubscriberDataRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onDeleteSubscriberDataRequest      ]]]]]]]]]]");
    }

    @Override
    public void onDeleteSubscriberDataResponse(DeleteSubscriberDataResponse request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onDeleteSubscriberDataResponse      ]]]]]]]]]]");
    }

    @Override
    public void onCheckImeiRequest(CheckImeiRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onCheckImeiRequest      ]]]]]]]]]]");
    }

    @Override
    public void onCheckImeiResponse(CheckImeiResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onCheckImeiResponse      ]]]]]]]]]]");
    }

    @Override
    public void onActivateTraceModeRequest_Mobility(ActivateTraceModeRequest_Mobility ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onActivateTraceModeRequest_Mobility      ]]]]]]]]]]");
    }

    @Override
    public void onActivateTraceModeResponse_Mobility(ActivateTraceModeResponse_Mobility ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onActivateTraceModeResponse_Mobility      ]]]]]]]]]]");
    }

    @Override
    public void onSendRoutingInformationRequest(SendRoutingInformationRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSendRoutingInformationRequest      ]]]]]]]]]]");
    }

    @Override
    public void onSendRoutingInformationResponse(SendRoutingInformationResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSendRoutingInformationResponse      ]]]]]]]]]]");
    }

    @Override
    public void onProvideRoamingNumberRequest(ProvideRoamingNumberRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onProvideRoamingNumberRequest      ]]]]]]]]]]");
    }

    @Override
    public void onProvideRoamingNumberResponse(ProvideRoamingNumberResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onProvideRoamingNumberResponse      ]]]]]]]]]]");
    }

    @Override
    public void onIstCommandRequest(IstCommandRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onIstCommandRequest      ]]]]]]]]]]");
    }

    @Override
    public void onIstCommandResponse(IstCommandResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onIstCommandResponse      ]]]]]]]]]]");
    }

    @Override
    public void onProvideSubscriberLocationRequest(ProvideSubscriberLocationRequest provideSubscriberLocationRequestIndication) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onProvideSubscriberLocationRequest      ]]]]]]]]]]");
    }

    @Override
    public void onProvideSubscriberLocationResponse(ProvideSubscriberLocationResponse provideSubscriberLocationResponseIndication) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onProvideSubscriberLocationResponse      ]]]]]]]]]]");
    }

    @Override
    public void onSubscriberLocationReportRequest(SubscriberLocationReportRequest subscriberLocationReportRequestIndication) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSubscriberLocationReportRequest      ]]]]]]]]]]");
    }

    @Override
    public void onSubscriberLocationReportResponse(SubscriberLocationReportResponse subscriberLocationReportResponseIndication) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSubscriberLocationReportResponse      ]]]]]]]]]]");
    }

    @Override
    public void onSendRoutingInfoForLCSRequest(SendRoutingInfoForLCSRequest sendRoutingInforForLCSRequestIndication) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSendRoutingInfoForLCSRequest      ]]]]]]]]]]");
    }

    @Override
    public void onSendRoutingInfoForLCSResponse(SendRoutingInfoForLCSResponse sendRoutingInforForLCSResponseIndication) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSendRoutingInfoForLCSResponse      ]]]]]]]]]]");
    }

    @Override
    public void onActivateTraceModeRequest_Oam(ActivateTraceModeRequest_Oam ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onActivateTraceModeRequest_Oam      ]]]]]]]]]]");
    }

    @Override
    public void onActivateTraceModeResponse_Oam(ActivateTraceModeResponse_Oam ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onActivateTraceModeResponse_Oam      ]]]]]]]]]]");
    }

    @Override
    public void onSendImsiRequest(SendImsiRequest ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSendImsiRequest      ]]]]]]]]]]");
    }

    @Override
    public void onSendImsiResponse(SendImsiResponse ind) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSendImsiResponse      ]]]]]]]]]]");
    }

    @Override
    public void onSendRoutingInfoForGprsRequest(SendRoutingInfoForGprsRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSendRoutingInfoForGprsRequest      ]]]]]]]]]]");
    }

    @Override
    public void onSendRoutingInfoForGprsResponse(SendRoutingInfoForGprsResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSendRoutingInfoForGprsResponse      ]]]]]]]]]]");
    }

    @Override
    public void onForwardShortMessageRequest(ForwardShortMessageRequest forwSmInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onForwardShortMessageRequest      ]]]]]]]]]]");
    }

    @Override
    public void onForwardShortMessageResponse(ForwardShortMessageResponse forwSmRespInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onForwardShortMessageResponse      ]]]]]]]]]]");
    }

    @Override
    public void onMoForwardShortMessageRequest(MoForwardShortMessageRequest moForwSmInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onMoForwardShortMessageRequest      ]]]]]]]]]]");
    }

    @Override
    public void onMoForwardShortMessageResponse(MoForwardShortMessageResponse moForwSmRespInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onMoForwardShortMessageResponse      ]]]]]]]]]]");
    }

    @Override
    public void onMtForwardShortMessageRequest(MtForwardShortMessageRequest mtForwSmInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onMtForwardShortMessageRequest      ]]]]]]]]]]");
    }

    @Override
    public void onMtForwardShortMessageResponse(MtForwardShortMessageResponse mtForwSmRespInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onMtForwardShortMessageResponse      ]]]]]]]]]]");
    }

    @Override
    public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest sendRoutingInfoForSMInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSendRoutingInfoForSMRequest      ]]]]]]]]]]");
    }

    @Override
    public void onSendRoutingInfoForSMResponse(SendRoutingInfoForSMResponse sendRoutingInfoForSMRespInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onSendRoutingInfoForSMResponse      ]]]]]]]]]]");
    }

    @Override
    public void onReportSMDeliveryStatusRequest(ReportSMDeliveryStatusRequest reportSMDeliveryStatusInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onReportSMDeliveryStatusRequest      ]]]]]]]]]]");
    }

    @Override
    public void onReportSMDeliveryStatusResponse(ReportSMDeliveryStatusResponse reportSMDeliveryStatusRespInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onReportSMDeliveryStatusResponse      ]]]]]]]]]]");
    }

    @Override
    public void onInformServiceCentreRequest(InformServiceCentreRequest informServiceCentreInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onInformServiceCentreRequest      ]]]]]]]]]]");
    }

    @Override
    public void onAlertServiceCentreRequest(AlertServiceCentreRequest alertServiceCentreInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onAlertServiceCentreRequest      ]]]]]]]]]]");
    }

    @Override
    public void onAlertServiceCentreResponse(AlertServiceCentreResponse alertServiceCentreInd) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onAlertServiceCentreResponse      ]]]]]]]]]]");
    }

    @Override
    public void onReadyForSMRequest(ReadyForSMRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onReadyForSMRequest      ]]]]]]]]]]");
    }

    @Override
    public void onReadyForSMResponse(ReadyForSMResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onReadyForSMResponse      ]]]]]]]]]]");
    }

    @Override
    public void onNoteSubscriberPresentRequest(NoteSubscriberPresentRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onNoteSubscriberPresentRequest      ]]]]]]]]]]");
    }
    
    @Override
    public void onRegisterSSRequest(RegisterSSRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onRegisterSSRequest      ]]]]]]]]]]");
    }

    @Override
    public void onRegisterSSResponse(RegisterSSResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onRegisterSSResponse      ]]]]]]]]]]");
   }

    @Override
    public void onEraseSSRequest(EraseSSRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onEraseSSRequest      ]]]]]]]]]]");
    }

    @Override
    public void onEraseSSResponse(EraseSSResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onEraseSSResponse      ]]]]]]]]]]");
    }

    @Override
    public void onActivateSSRequest(ActivateSSRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onActivateSSRequest      ]]]]]]]]]]");
    }

    @Override
    public void onActivateSSResponse(ActivateSSResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onActivateSSResponse      ]]]]]]]]]]");
    }

    @Override
    public void onDeactivateSSRequest(DeactivateSSRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onDeactivateSSRequest      ]]]]]]]]]]");
    }

    @Override
    public void onDeactivateSSResponse(DeactivateSSResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onDeactivateSSResponse      ]]]]]]]]]]");
    }

    @Override
    public void onInterrogateSSRequest(InterrogateSSRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onInterrogateSSRequest      ]]]]]]]]]]");
    }

    @Override
    public void onInterrogateSSResponse(InterrogateSSResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onInterrogateSSResponse      ]]]]]]]]]]");
    }

    @Override
    public void onGetPasswordRequest(GetPasswordRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onGetPasswordRequest      ]]]]]]]]]]");
    }

    @Override
    public void onGetPasswordResponse(GetPasswordResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onGetPasswordResponse      ]]]]]]]]]]");
    }

    @Override
    public void onRegisterPasswordRequest(RegisterPasswordRequest request) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onRegisterPasswordRequest      ]]]]]]]]]]");
    }

    @Override
    public void onRegisterPasswordResponse(RegisterPasswordResponse response) {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        logger.debug("[[[[[[[[[[   onRegisterPasswordResponse      ]]]]]]]]]]");
    }
    
    public void onServiceStarted() {
        logger.debug("[[[[[[[[[[    onServiceStarted      ]]]]]]]]]]");
    }

    public void onServiceStopped() {
        logger.debug("[[[[[[[[[[    onServiceStopped      ]]]]]]]]]]");
    }

    public void onRemoveAllResources() {
        logger.debug("[[[[[[[[[[    onRemoveAllResources      ]]]]]]]]]]");
    }

    public void onServerAdded(org.mobicents.protocols.api.Server server) {
        logger.debug("[[[[[[[[[[    onServerAdded      ]]]]]]]]]]");
    }

    public void onServerRemoved(org.mobicents.protocols.api.Server server) {
        logger.debug("[[[[[[[[[[    onServerRemoved      ]]]]]]]]]]");
    }

    public void onAssociationAdded(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationAdded      ]]]]]]]]]]");
    }

    public void onAssociationRemoved(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationRemoved      ]]]]]]]]]]");
    }

    public void onAssociationStarted(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationStarted      ]]]]]]]]]]");
    }

    public void onAssociationStopped(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationStopped      ]]]]]]]]]]");
    }

    public void onAssociationUp(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationUp      ]]]]]]]]]]");
        if (asctn != null) {
            logger.warn(String.format("SCTP AssociationUp name=%s peer=%s", asctn.getName(), asctn.getPeerAddress()));
        }
    }

    public void onAssociationDown(Association asctn) {
        logger.debug("[[[[[[[[[[    onAssociationDown      ]]]]]]]]]]");
        if (asctn != null) {
            logger.warn(String.format("SCTP AssociationDown name=%s peer=%s", asctn.getName(), asctn.getPeerAddress()));
        }
    }
    
    public void onMtp3EndCongestionMessage(Mtp3EndCongestionPrimitive mecp) {
        logger.debug("[[[[[[[[[[    onMtp3EndCongestionMessage      ]]]]]]]]]]");
    }

    public void onCoordResponse(int i, int i1) {
        logger.debug("[[[[[[[[[[    onCoordResponse      ]]]]]]]]]]");
    }

    public void onPcState(int i, SignallingPointStatus sps, Integer intgr, RemoteSccpStatus rss) {
        logger.debug("[[[[[[[[[[    onPcState      ]]]]]]]]]]");
    }

    public void onNetworkIdState(int i, NetworkIdState nis) {
        logger.debug("[[[[[[[[[[    onNetworkIdState      ]]]]]]]]]]");
    }

    public void onAnyTimeSubscriptionInterrogationRequest(AnyTimeSubscriptionInterrogationRequest atsir) {
        logger.debug("[[[[[[[[[[    onAnyTimeSubscriptionInterrogationRequest      ]]]]]]]]]]");
    }

    public void onAnyTimeSubscriptionInterrogationResponse(AnyTimeSubscriptionInterrogationResponse atsir) {
        logger.debug("[[[[[[[[[[    onAnyTimeSubscriptionInterrogationResponse      ]]]]]]]]]]");
    }

    /**
     * Method to return status of the firewall. 
     * Status can be retrieved over REST API.
     * 
     */
    public static String getStatus() {
        String s = "";
        
        s += "Jetty Server Status = " + jettyServer.getState() + "\n";
        s += "Jetty Date = " + jettyServer.getDateField().toString() + "\n";
        s += "Jetty URI = " + jettyServer.getURI().toString() + "\n";
        s += "\n";
        s += "SCTP Associations\n";
        for (Map.Entry<String, Association> a : sctpManagement.getAssociations().entrySet()) {
            s += " Name = " + a.getKey() + "\n";
            s += " Details = " + a.getValue().toString() + "\n";
            s += " isStarted = " + a.getValue().isStarted() + "\n";
            s += " isConnected = " + a.getValue().isConnected() + "\n";
        }
        s += "\n";
        s += "SCTP Servers = " + sctpManagement.getServers().toString() + "\n";
        s += "\n";
        //s += "M3UA Server ASP = " + serverM3UAMgmt.toString() + "\n";
        s += "M3UA Server\n";
        for (As a : serverM3UAMgmt.getAppServers()) {
            s += " Name = " + a.getName() + "\n";
            s += " isConnected = " + a.isConnected() + "\n";
            s += " isUp = " + a.isUp() + "\n";
        }
        s += "M3UA Server Route = " + serverM3UAMgmt.getRoute().toString() + "\n";
        s += "\n";
        //s += "M3UA Client ASP = " + clientM3UAMgmt.toString() + "\n";
        s += "M3UA Client\n";
        for (As a : clientM3UAMgmt.getAppServers()) {
            s += " Name = " + a.getName() + "\n";
            s += " isConnected = " + a.isConnected() + "\n";
            s += " isUp = " + a.isUp() + "\n";
        }
        s += "M3UA Client Route = " + clientM3UAMgmt.getRoute().toString() + "\n";
        s += "\n";
        s += "SCCP M3UA User Parts = " + sccpStack.getSccpResource().getRemoteSpcs().toString() + "\n";
        s += "\n";
        
        s += "OS statistics\n";
        s += " Available processors (cores): " + Runtime.getRuntime().availableProcessors() + "\n";
        s += " Free memory (bytes): " + Runtime.getRuntime().freeMemory() + "\n";
        long maxMemory = Runtime.getRuntime().maxMemory();
        s += " Maximum memory (bytes): " + (maxMemory == Long.MAX_VALUE ? "no limit" : maxMemory) + "\n";
        s += " Total memory available to JVM (bytes): " + Runtime.getRuntime().totalMemory() + "\n";
        File[] roots = File.listRoots();
        /* For each filesystem root, print some info */
        for (File root : roots) {
            s += " File system root: " + root.getAbsolutePath() + "\n";
            s += " Total space (bytes): " + root.getTotalSpace() + "\n";
            s += " Free space (bytes): " + root.getFreeSpace() + "\n";
            s += " Usable space (bytes): " + root.getUsableSpace() + "\n";
        }
        s += "\n";
        s += "Network interfaces\n";
        try {
            Enumeration<NetworkInterface> nets;
            nets = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface netint : Collections.list(nets)) {
                s += " Display name: " + netint.getDisplayName() + "\n";
                s += " Name: " + netint.getName() + "\n";
                Enumeration<InetAddress> inetAddresses = netint.getInetAddresses();
                for (InetAddress inetAddress : Collections.list(inetAddresses)) {
                    s += " InetAddress: " + inetAddress + "\n";
                }
            }
        } catch (SocketException ex) {
            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return s;
    }
    
    /**
     * Method to split byte array 
     * 
     * @param bytes original byte array
     * @param chunkSize chunk size
     * @return two dimensional byte array
     */
    private byte[][] splitByteArray(byte[] bytes, int chunkSize) {
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
    private byte[] concatByteArray(byte[] a, byte[] b) {
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
    
}
