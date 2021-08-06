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

import com.p1sec.sigfw.SigFW_interface.CryptoInterface;
import sigfw.common.ExternalFirewallRules;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import org.apache.log4j.Logger;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.asn.AsnInputStream;
import org.mobicents.protocols.asn.Tag;
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
import org.mobicents.protocols.ss7.sccp.message.SccpMessage;
import org.mobicents.protocols.ss7.sccp.parameter.GlobalTitle;
import org.mobicents.protocols.ss7.sccp.parameter.ParameterFactory;
import org.mobicents.protocols.ss7.sccp.parameter.ReturnCause;
import org.mobicents.protocols.ss7.sccp.parameter.ReturnCauseValue;
import org.mobicents.protocols.ss7.tcap.api.TCAPStack;
import org.mobicents.protocols.ss7.tcap.asn.EncodeException;
import org.mobicents.protocols.ss7.tcap.asn.InvokeImpl;
import org.mobicents.protocols.ss7.tcap.asn.ReturnResultLastImpl;
import static org.mobicents.protocols.ss7.tcap.asn.comp.ComponentType.ReturnResultLast;
import org.mobicents.protocols.ss7.tcap.asn.comp.OperationCode;
import org.mobicents.protocols.ss7.tcap.asn.comp.ReturnResultLast;
import static ss7fw.SS7FirewallConfig.keyFactoryRSA;
import sigfw.connectorIDS.ConnectorIDS;
import sigfw.connectorIDS.ConnectorIDSModuleRest;
import sigfw.connectorMThreat.ConnectorMThreat;
import sigfw.connectorMThreat.ConnectorMThreatModuleRest;
import com.p1sec.sigfw.SigFW_interface.FirewallRulesInterface;
import java.security.interfaces.ECPublicKey;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
//import javafx.util.Pair;
import com.sun.tools.javac.util.Pair;
import java.io.FileInputStream;
import java.net.DatagramPacket;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import ss7fw.DatagramOverSS7Packet;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.mobicents.protocols.sctp.netty.NettySctpManagementImpl;
import sigfw.common.Crypto;
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
    
    // Executor Threads
    ExecutorService threadPool = Executors.newFixedThreadPool(16);

    // Unit Tests flags
    public static boolean unitTesting = false;
    public static boolean unitTestingFlags_sendSccpErrorMessage = false;
    public static boolean unitTestingFlags_sendSccpMessage = false;
    
    // SCTP
    private static NettySctpManagementImpl sctpManagement;

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
    
    // Externel Firewall Rules
    FirewallRulesInterface externalFirewallRules = new ExternalFirewallRules();
    
    // Crypto Module
    CryptoInterface crypto = new Crypto();
    
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
    // Encryption Autodiscovery Reverse
    // Value: Dest_Realm
    // Key: E2E ID
    private static Map<String, Long> encryption_autodiscovery_sessions_reverse = ExpiringMap.builder()
                                                .expiration(60, TimeUnit.SECONDS)
                                                .build();
    
    // DTLS Session
    // Key: E2E ID
    // Value: Dest_Realm
    //private static Map<Long, String> dtls_sessions = ExpiringMap.builder()
    //                                            .expiration(60, TimeUnit.SECONDS)
    //                                            .build();
    
    public static KeyManagerFactory kmf = null;
    
    private static int DTLS_BUFFER_SIZE = 64*1024;
    private static int DTLS_MAX_HANDSHAKE_LOOPS = 200;
    private static int DTLS_MAXIMUM_PACKET_SIZE = 10*1024;
    private static int DTLS_SOCKET_TIMEOUT = 5 * 1000; // in millis
    private static int DTLS_SOCKET_THREAD_SLEEP = 100; // in millis
    private static int DTLS_MAX_SESSION_DURATION = 60*60; // in seconds, after the new handshake is required
    private static int DTLS_MAX_HANDSHAKE_DURATION = 10; // in seconds, after the handshake SSL engine is dropped. Has to be shorter than half of DTLS_MAX_SESSION_DURATION
    //private static Exception dtls_clientException = null;
    //private static Exception dtls_serverException = null;
    private static String dtls_pathToStores = "./";
    private static String dtls_keyStoreFile = "keystore";
    private static String dtls_trustStoreFile = "truststore";
    private static String dtls_passwd = "keystore";
    public static String dtls_keyStoreAlias = "keystore";
    private static String dtls_keyFilename =
            System.getProperty("test.src", ".") + "/" + dtls_pathToStores +
                "/" + dtls_keyStoreFile;
    private static String dtls_trustFilename =
            System.getProperty("test.src", ".") + "/" + dtls_pathToStores +
                "/" + dtls_trustStoreFile;
    
    // protectedAVPs codes used for DTLS encryption
    List<Integer> protectedAVPCodes = new ArrayList<Integer>(Arrays.asList(
            1,  // User-Name AVP
            1600  // MME-Location-Information
    ));

            
    
    // SSL engines stored for peers used by DTLS
    // this expiring, used to trigger new handshakes after they expire
    private static Map<String, SSLEngine> dtls_engine_expiring_server = ExpiringMap.builder()
                                                .expiration(DTLS_MAX_SESSION_DURATION, TimeUnit.SECONDS)
                                                .build(); // <peer_realm, SSLEngine> 
    private static Map<String, SSLEngine> dtls_engine_expiring_client = ExpiringMap.builder()
                                                .expiration(DTLS_MAX_SESSION_DURATION, TimeUnit.SECONDS)
                                                .build(); // <peer_realm, SSLEngine> 
    // SSL engines stored for peers used by DTLS
    // this is permanent, used for actual encryption
    // 2 DTLS sessions, in and out. Server side is used for decrypt, client side for encrypt.
    private static Map<String, SSLEngine> dtls_engine_permanent_server = new ConcurrentHashMap<>(); // <peer_realm, SSLEngine>
    private static Map<String, SSLEngine> dtls_engine_permanent_client = new ConcurrentHashMap<>(); // <peer_realm, SSLEngine>
    // DTLS SSL engines being handshaked
    private static Map<String, SSLEngine> dtls_engine_handshaking_server = ExpiringMap.builder()
                                                .expiration(DTLS_MAX_HANDSHAKE_DURATION, TimeUnit.SECONDS)
                                                .build(); // <peer_realm, SSLEngine>
    // DTLS SSL engines being handshaked
    private static Map<String, SSLEngine> dtls_engine_handshaking_client = ExpiringMap.builder()
                                                .expiration(DTLS_MAX_HANDSHAKE_DURATION, TimeUnit.SECONDS)
                                                .build(); // <peer_realm, SSLEngine> 
    // DTLS handshake thread running indicator
    //private static Map<String, Thread> dtls_handshake_treads = ExpiringMap.builder()
    //                                            .expiration(DTLS_MAX_HANDSHAKE_DURATION, TimeUnit.SECONDS)
    //                                            .build(); // <peer_realm, Thread> 
    
    // DTLS client initialization timer, do not initiate new DTLS handshake till this timer
    // Value: Dest_Realm
    // Key: E2E ID
    private static Map<String, Long> dtls_handshake_timer = ExpiringMap.builder()
                                                .expiration(DTLS_MAX_HANDSHAKE_DURATION*2, TimeUnit.SECONDS)
                                                .build();
    
    
    private static Map<String, ConcurrentLinkedQueue<DatagramOverSS7Packet>> datagramOverSS7Socket_inbound_server = ExpiringMap.builder()
                                                .expiration(DTLS_MAX_HANDSHAKE_DURATION, TimeUnit.SECONDS)
                                                .build(); // <peer_realm, SSLEngine> //new ConcurrentHashMap<>(); //new ConcurrentLinkedQueue<>();
    private static Map<String, ConcurrentLinkedQueue<DatagramOverSS7Packet>> datagramOverSS7Socket_inbound_client = ExpiringMap.builder()
                                                .expiration(DTLS_MAX_HANDSHAKE_DURATION, TimeUnit.SECONDS)
                                                .build(); // <peer_realm, SSLEngine> //new ConcurrentHashMap<>(); //new ConcurrentLinkedQueue<>();
    //private static ConcurrentLinkedQueue<DatagramOverSS7Packet> datagramOverSS7Socket_outbound = new ConcurrentLinkedQueue<>();
    
    
    

    static Random randomGenerator = new Random();
    
    static final private Long OC_AUTO_ENCRYPTION = 99L;
    static final private Long OC_DTLS_HANDSHAKE_CLIENT = 97L;
    static final private Long OC_DTLS_HANDSHAKE_SERVER = 98L;
    static final private Long OC_DTLS_DATA = 96L;
    
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
        this.sctpManagement = new org.mobicents.protocols.sctp.netty.NettySctpManagementImpl(
                (String)SS7FirewallConfig.get("$.sigfw_configuration.sctp.sctp_management_name")
        );
        
        this.sctpManagement.setSingleThread(true);
        
        this.sctpManagement.setPersistDir(persistDir);
        
        this.sctpManagement.setOptionSctpInitMaxstreams_MaxInStreams(Integer.parseInt((String)SS7FirewallConfig.get("$.sigfw_configuration.sctp.sctp_max_in_streams")));
        this.sctpManagement.setOptionSctpInitMaxstreams_MaxOutStreams(Integer.parseInt((String)SS7FirewallConfig.get("$.sigfw_configuration.sctp.sctp_max_out_streams")));
        
        this.sctpManagement.start();
        this.sctpManagement.setConnectDelay(10000);
        //this.sctpManagement.setMaxIOErrors(30);
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
        
        // 2. Create Client <-> FW Association
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
        
        
        // 3. Create FW <-> Server Association
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
        
        // this.serverM3UAMgmt.setDeliveryMessageThreadCount(16);
        
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
        
        // this.clientM3UAMgmt.setDeliveryMessageThreadCount(16);
        
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
        //serverM3UAMgmt.addMtp3UserPartListener(this);
        //clientM3UAMgmt.addMtp3UserPartListener(this);
        
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
        //SS7Firewall.tcapStack.getProvider().addTCListener(this);
        
        // TODO uncomment to get MAP listeners
        //this.tcapStack.start();
        //this.tcapStack.setDialogIdleTimeout(60000);
        //this.tcapStack.setInvokeTimeout(30000);
        //this.tcapStack.setMaxDialogs(2000);
        logger.debug("Initialized TCAP Stack ....");
        
        
        this.mapProvider = this.mapStack.getMAPProvider();
        
        /*this.mapProvider.addMAPDialogListener(this);
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
        this.mapProvider.getMAPServiceSms().acivate();*/
        
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
        
        // Initialize SigFW Extensions
        try {
            logger.info("Trying to load SigFW extensions from: " + "file://" + System.getProperty("user.dir")  + "/src/main/resources/SigFW_extension-1.0.jar");
            
            // Constructing a URL form the path to JAR
            URL u = new URL("file://" + System.getProperty("user.dir")  + "/src/main/resources/SigFW_extension-1.0.jar");
            
            // Creating an instance of URLClassloader using the above URL and parent classloader 
            ClassLoader loader  = URLClassLoader.newInstance(new URL[]{u}, ExternalFirewallRules.class.getClassLoader());

            // Returns the class object
            Class<?> mainClass = Class.forName("com.p1sec.sigfw.SigFW_extension.rules.ExtendedFirewallRules", true, loader);
            externalFirewallRules = (FirewallRulesInterface) mainClass.getDeclaredConstructor().newInstance();
            
            // Returns the class object
            Class<?> mainClassCrypto = Class.forName("com.p1sec.sigfw.SigFW_extension.crypto.ExtendedCrypto", true, loader);
            crypto = (CryptoInterface) mainClassCrypto.getDeclaredConstructor().newInstance();

            
            logger.info("Sucessfully loaded SigFW extensions ....");
        
        } catch (Exception e) {
            logger.info("Failed to load SigFW extensions: " + e.toString());
        }
        // End of SigFW Extensions
        
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
    public void onMessage(final SccpDataMessage msg) {
        
        logger.debug("[[[[[[[[[[    Sccp Message Recieved MainThread     ]]]]]]]]]]");
        
        threadPool.execute(new Runnable() {
            @Override
            public void run() { 
                           
                logger.debug("[[[[[[[[[[    Sccp Message Recieved      ]]]]]]]]]]");
                
                SccpDataMessage message = msg;
                
                logger.debug(message.toString());

                int dpc = message.getIncomingDpc();
                int opc = message.getIncomingOpc();
                int sls = message.getSls();
                int ni = message.getNetworkId();

                Mtp3UserPart mup = SS7Firewall.serverM3UAMgmt;        
                Mtp3UserPart mupReturn = SS7Firewall.clientM3UAMgmt;
                
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
                        mup = SS7Firewall.serverM3UAMgmt;
                        mupReturn = SS7Firewall.clientM3UAMgmt;
                        break;
                    }
                }
                for (int i = 0; i < SS7FirewallConfig.m3ua_client_remote_pc.size(); i++) {
                    if (dpc == Integer.parseInt(SS7FirewallConfig.m3ua_client_remote_pc.get(i))) {
                        mup = SS7Firewall.clientM3UAMgmt;
                        mupReturn = SS7Firewall.serverM3UAMgmt;
                        break;
                    }
                }

                //LongMessageRule lmr = this.sccpStack.getRouter().findLongMessageRule(dpc);
                LongMessageRule lmr = null;
                for (Map.Entry<Integer, LongMessageRule> e : SS7Firewall.sccpStack.getRouter().getLongMessageRules().entrySet()) {
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
                    
                    OperationCodeImpl oc = null;
                    if (comps != null) {
                        for (Component comp : comps) {
                            if (comp == null) {
                                continue;
                            }

                            switch (comp.getType()) {
                            case Invoke:
                                Invoke inv = (Invoke) comp;

                                // Operation Code
                                oc = (OperationCodeImpl) inv.getOperationCode();
                                break;
                            }
                        }
                    }

                    // ------------ TCAP decryption -------------
                    
                    boolean needDTLSHandshake = false;
                    String needDTLSHandshakeReason = "";
                    
                    if (message.getCalledPartyAddress() != null && message.getCalledPartyAddress().getGlobalTitle() != null
                            && oc != null && oc.getLocalOperationCode() != OC_DTLS_HANDSHAKE_CLIENT && oc.getLocalOperationCode() != OC_DTLS_HANDSHAKE_SERVER ) { 
                            
                        // DTLS decryption
                        if (oc.getLocalOperationCode() == OC_DTLS_DATA && dtls_engine_permanent_server.containsKey(getGTPrefix(message.getCallingPartyAddress().getGlobalTitle().getDigits()))) {
                            
                            AbstractMap.SimpleEntry<SccpDataMessage, String> p = ss7DTLSDecrypt(message, comps, dtls_engine_permanent_server.get(getGTPrefix(message.getCallingPartyAddress().getGlobalTitle().getDigits())));
                            if (p != null) {
                                SccpDataMessage m = p.getKey();
                                String r = p.getValue();
                                if (!r.equals("")) {
                                    needDTLSHandshake = true;

                                    needDTLSHandshakeReason = "needDTLSHandshake indicated, because failed to decrypt Invoke message from GT: " + message.getCallingPartyAddress().getGlobalTitle().getDigits();
                                    
                                    firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, r, lua_hmap);
                                    return;
                                }
                                if (!dtls_engine_expiring_server.containsKey(getGTPrefix(message.getCallingPartyAddress().getGlobalTitle().getDigits()))) {
                                    needDTLSHandshake = true;

                                    needDTLSHandshakeReason = "needDTLSHandshake indicated, because session has expired for GT: " + message.getCallingPartyAddress().getGlobalTitle().getDigits();
                                }

                                message = m;
                                
                                // Change back to SCCP UDT from XUDT if possible
                                if (message.getData().length < 240) {
                                    lmrt = LongMessageRuleType.LONG_MESSAGE_FORBBIDEN;
                                }
                            }
                        }
                        /*// No DTLS engine, but recieved DTLS encrypted data
                        else if (oc.getLocalOperationCode() == OC_DTLS_DATA) {
                            needDTLSHandshakeReason = "needDTLSHandshake indicated, because no DTLS engine, but recieved Request with DTLS encrypted data from GT: " + message.getCalledPartyAddress().getGlobalTitle().getDigits();
                            
                            needDTLSHandshake = true;
                        }*/
                        // Asymmetric decryption
                        else if (oc.getLocalOperationCode() == Crypto.OC_ASYNC_ENCRYPTION) { 
                            KeyPair keyPair = SS7FirewallConfig.simpleWildcardFind(SS7FirewallConfig.called_gt_decryption, message.getCalledPartyAddress().getGlobalTitle().getDigits());
                            if (keyPair != null) {
                                AbstractMap.SimpleEntry<SccpDataMessage, String> p = crypto.tcapDecrypt(message, comps, SS7Firewall.sccpMessageFactory, keyPair);
                                
                                
                                if (p != null) {
                                    message = p.getKey();
                                    
                                    // Change back to SCCP UDT from XUDT if possible
                                    if (message.getData().length < 240) {
                                        lmrt = LongMessageRuleType.LONG_MESSAGE_FORBBIDEN;
                                    }
                                    
                                    String r = p.getValue();
                                    if (!r.equals("")) {
                                        firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, r, lua_hmap);
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    // ------------------------------------------
                    
                    // Initiate DTLS handshake backwards towards Calling GT
                    if (needDTLSHandshake
                        && SS7FirewallConfig.dtls_encryption.equals("true")) {
                        if (!dtls_handshake_timer.containsKey(message.getCallingPartyAddress().getGlobalTitle().getDigits())) {
                            // Only if no handshaking is ongoing
                            if (!dtls_engine_handshaking_client.containsKey(getGTPrefix(message.getCallingPartyAddress().getGlobalTitle().getDigits()))) {

                                logger.info("Initiate DTLS handshake client side, backwards towards Calling GT: " + message.getCallingPartyAddress().getGlobalTitle().getDigits());
                                logger.info("Initiate DTLS handshake reason: " + needDTLSHandshakeReason);

                                final String calling_gt = String.valueOf(message.getCallingPartyAddress().getGlobalTitle().getDigits());

                                final Mtp3UserPart m = mupReturn;
                                
                                Thread t = new Thread(new Runnable() {
                                    @Override
                                    public void run() {
                                        try {

                                            // Create engine
                                            try {
                                                dtls_engine_handshaking_client.put(getGTPrefix(calling_gt), dtls_createSSLEngine(true));

                                            } catch (Exception ex) {
                                                java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                                            }

                                            // Create socket if does not exist
                                            if (!datagramOverSS7Socket_inbound_client.containsKey(getGTPrefix(calling_gt))) {
                                                datagramOverSS7Socket_inbound_client.put(getGTPrefix(calling_gt), new ConcurrentLinkedQueue<DatagramOverSS7Packet>());
                                            }

                                            dtls_handshake(dtls_engine_handshaking_client.get(getGTPrefix(calling_gt)), datagramOverSS7Socket_inbound_client.get(getGTPrefix(calling_gt)), m, opc, dpc, sls, ni, calling_gt, "client", false);
                                        } catch (Exception ex) {
                                            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                                        }
                                    }
                                });
                                t.start();
                            }
                                
                            logger.debug("dtls_sessions_reverse.put " + message.getCallingPartyAddress().getGlobalTitle().getDigits() + " " + null);
                            dtls_handshake_timer.put(message.getCallingPartyAddress().getGlobalTitle().getDigits(), null);
 
                            
                            
                          }
                    }
                    // ------------------------------------------
                    
                    // --------------- TCAP signature ---------------
                    if (message.getCallingPartyAddress() != null && message.getCallingPartyAddress().getGlobalTitle() != null 
                            && oc != null && oc.getLocalOperationCode() != OC_DTLS_HANDSHAKE_CLIENT && oc.getLocalOperationCode() != OC_DTLS_HANDSHAKE_SERVER && oc.getLocalOperationCode() != OC_DTLS_DATA) { 
                        // --------------- TCAP verify  ---------------
                        int signature_ok = -1;  // no key
                        PublicKey publicKey = SS7FirewallConfig.simpleWildcardFind(SS7FirewallConfig.calling_gt_verify, message.getCallingPartyAddress().getGlobalTitle().getDigits());
                        if (publicKey != null) {
                            signature_ok = crypto.tcapVerify(message, tcb, comps, publicKey) ;
                            if (signature_ok == 0) {
                                // Drop not correctly signed messages
                                //logger.info("============ Wrong TCAP signature, message blocked. Calling GT = " + message.getCallingPartyAddress().getGlobalTitle().getDigits() + " ============");

                                firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "TCAP FW: Wrong TCAP signature", lua_hmap);
                                return;
                            }
                            // Change back to SCCP UDT from XUDT if possible
                            if (message.getData().length < 240) {
                                lmrt = LongMessageRuleType.LONG_MESSAGE_FORBBIDEN;
                            }
                        }
                        // --------------------------------------------
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


                                    // Capabilities
                                    // TODO
                                    Parameter p1 = TcapFactory.createParameter();
                                    p1.setTagClass(Tag.CLASS_PRIVATE);
                                    p1.setPrimitive(true);
                                    p1.setTag(Tag.STRING_OCTET);
                                    p1.setData("Av1".getBytes());

                                    // GT prefix
                                    Parameter p2 = TcapFactory.createParameter();
                                    p2.setTagClass(Tag.CLASS_PRIVATE);
                                    p2.setPrimitive(true);
                                    p2.setTag(Tag.STRING_OCTET);
                                    byte[] d2 = key.getBytes();
                                    p2.setData(d2);

                                    // Public key type
                                    String publicKeyType = "";
                                    if (myKeyPair.getPublic() instanceof RSAPublicKey) {
                                        publicKeyType = "RSA";
                                    } else if (myKeyPair.getPublic() instanceof ECPublicKey) {
                                        publicKeyType = "EC";
                                    }
                                    Parameter p3 = TcapFactory.createParameter();
                                    p3.setTagClass(Tag.CLASS_PRIVATE);
                                    p3.setPrimitive(true);
                                    p3.setTag(Tag.STRING_OCTET);
                                    p3.setData(publicKeyType.getBytes());

                                    // Public key
                                    Parameter p4 = TcapFactory.createParameter();
                                    p4.setTagClass(Tag.CLASS_PRIVATE);
                                    p4.setPrimitive(true);
                                    p4.setTag(Tag.STRING_OCTET);
                                    byte[] d4 = myKeyPair.getPublic().getEncoded();
                                    p4.setData(d4);

                                    Parameter p = TcapFactory.createParameter();
                                    p.setTagClass(Tag.CLASS_UNIVERSAL);
                                    p.setTag(0x04);
                                    p.setParameters(new Parameter[] { p1, p2, p3, p4});
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
                                    SccpDataMessage m = SS7Firewall.sccpMessageFactory.createDataMessageClass0(message.getCallingPartyAddress(), message.getCalledPartyAddress(), message.getData(), message.getOriginLocalSsn(), false, null, null);
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
                            
                                                    
                            // DTLS processing inbound handshake messages
                            // Only targeting HPLMN
                            if ((oc.getLocalOperationCode() == OC_DTLS_HANDSHAKE_CLIENT || oc.getLocalOperationCode() == OC_DTLS_HANDSHAKE_SERVER)
                                && SS7FirewallConfig.dtls_encryption.equals("true")
                                && SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.hplmn_gt, message.getCalledPartyAddress().getGlobalTitle().getDigits())
                                && !SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.hplmn_gt, message.getCallingPartyAddress().getGlobalTitle().getDigits())
                                        ) {

                                        
                                logger.info("Received DTLS handshake message from GT: " + message.getCallingPartyAddress().getGlobalTitle().getDigits());

                                // Request (client -> server)
                                if (oc.getLocalOperationCode() == OC_DTLS_HANDSHAKE_CLIENT) {
                                //if (msg.isRequest()) {

                                    // Create socket if does not exists
                                    if (!datagramOverSS7Socket_inbound_server.containsKey(getGTPrefix(message.getCallingPartyAddress().getGlobalTitle().getDigits()))) {
                                        datagramOverSS7Socket_inbound_server.put(getGTPrefix(message.getCallingPartyAddress().getGlobalTitle().getDigits()), new ConcurrentLinkedQueue<DatagramOverSS7Packet>());
                                    }

                                    Parameter p = inv.getParameter();
                                    Parameter[] params = p.getParameters();
                                    if (params != null && params.length >= 1) {

                                        // DTLS data
                                        Parameter p1 = params[0];

                                        datagramOverSS7Socket_inbound_server.get(getGTPrefix(message.getCallingPartyAddress().getGlobalTitle().getDigits())).add(new DatagramOverSS7Packet(message.getCallingPartyAddress().getGlobalTitle().getDigits(), new DatagramPacket(p1.getData(), p1.getData().length)));
                                    
                                    }

                                    boolean needHandshake = false;
                                    String needHandshakeReason = "";

                                    try {

                                        // new handshaking peer
                                        if(!dtls_engine_handshaking_server.containsKey(getGTPrefix(message.getCallingPartyAddress().getGlobalTitle().getDigits()))) {
                                            needHandshake = true;

                                            needHandshakeReason = "needDTLSHandshake indicated, because new handshaking client detected. Peer: " + message.getCallingPartyAddress().getGlobalTitle().getDigits();
                                        }
                                        // no thread exist
                                        /*else if (!dtls_handshake_treads.containsKey(orig_realm)){
                                            needHandshake = true;

                                            needHandshakeReason = "Initiate DTLS, because handshaking thread does not exist anymore. Peer: " + orig_realm;
                                        }*/
                                        /*// thread not active
                                        else if (!dtls_handshake_treads.get(orig_realm).isAlive()){
                                            needHandshake = true;

                                            needHandshakeReason = "Initiate DTLS, because handshaking thread is not alive. Peer: " + orig_realm;
                                        }*/
                                        /*// NOT_HANDSHAKING status
                                        else if (dtls_engine.get(orig_realm).getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING){
                                            needHandshake = true;

                                            needHandshakeReason = "Initiate DTLS, because in NOT_HANDSHAKING status";
                                        }*/

                                        // dispatch handshake in new thread
                                        if(needHandshake) {
                                            // Only if no server handshaking is ongoing

                                            if (/*(!dtls_handshake_treads.containsKey(orig_realm) || !dtls_handshake_treads.get(orig_realm).isAlive())
                                                    && */!dtls_engine_handshaking_server.containsKey(getGTPrefix(getGTPrefix(message.getCallingPartyAddress().getGlobalTitle().getDigits())))) {

                                                logger.info("Initiate DTLS handshake server side for peer: " + message.getCallingPartyAddress().getGlobalTitle().getDigits());
                                                logger.info("Initiate DTLS handshake reason: " + needHandshakeReason);

                                                final String calling_gt = String.valueOf(message.getCallingPartyAddress().getGlobalTitle().getDigits());

                                                final Mtp3UserPart m = mupReturn;

                                                Thread t = new Thread(new Runnable() {
                                                    @Override
                                                    public void run() {
                                                        try {
                                                            dtls_engine_handshaking_server.put(getGTPrefix(calling_gt), dtls_createSSLEngine(false));

                                                            dtls_handshake(dtls_engine_handshaking_server.get(getGTPrefix(calling_gt)), datagramOverSS7Socket_inbound_server.get(getGTPrefix(calling_gt)), /*datagramOverDiameterSocket_outbound*/ m, opc, dpc, sls, ni, calling_gt, "server", false);
                                                        } catch (Exception ex) {
                                                            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                                                        }
                                                    }
                                                });
                                                t.start();

                                            }

                                        }

                                    } catch (Exception ex) {
                                        java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                                    }
                                } 
                                // Answer (server -> client)
                                else if (oc.getLocalOperationCode() == OC_DTLS_HANDSHAKE_SERVER) {
                                //else {

                                    // Create socket if does not exists
                                    if (!datagramOverSS7Socket_inbound_client.containsKey(getGTPrefix(message.getCallingPartyAddress().getGlobalTitle().getDigits()))) {
                                        datagramOverSS7Socket_inbound_client.put(getGTPrefix(message.getCallingPartyAddress().getGlobalTitle().getDigits()), new ConcurrentLinkedQueue<DatagramOverSS7Packet>());
                                    }

                                    Parameter p = inv.getParameter();
                                    Parameter[] params = p.getParameters();
                                    if (params != null && params.length >= 1) {

                                        // DTLS data
                                        Parameter p1 = params[0];

                                        datagramOverSS7Socket_inbound_client.get(getGTPrefix(message.getCallingPartyAddress().getGlobalTitle().getDigits())).add(new DatagramOverSS7Packet(message.getCallingPartyAddress().getGlobalTitle().getDigits(), new DatagramPacket(p1.getData(), p1.getData().length)));

                                    }
                                }
                                
                                
                                // produce DTLS SS7 Result message
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


                                // TODO
                                Parameter p1 = TcapFactory.createParameter();
                                p1.setTagClass(Tag.CLASS_PRIVATE);
                                p1.setPrimitive(true);
                                p1.setTag(Tag.STRING_OCTET);
                                p1.setData("Av1".getBytes());

                                Parameter p = TcapFactory.createParameter();
                                p.setTagClass(Tag.CLASS_UNIVERSAL);
                                p.setTag(0x04);
                                p.setParameters(new Parameter[] { p1});
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
                                SccpDataMessage m = SS7Firewall.sccpMessageFactory.createDataMessageClass0(message.getCallingPartyAddress(), message.getCalledPartyAddress(), message.getData(), message.getOriginLocalSsn(), false, null, null);
                                m.setData(_d);

                                logger.info("============ DTLS handshake Sending Result ============ ");

                                // Use XUDT if required
                                if (m.getData().length >= 240) {
                                    l = LongMessageRuleType.XUDT_ENABLED;
                                }
                                sendSccpMessage(mupReturn, dpc, opc, sls, ni, l, m);
                                return;
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
                            if (oc != null) {
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
                            
                            
                            // DTLS answer messages
                            // Only targeting HPLMN
                            if ((oc.getLocalOperationCode() == OC_DTLS_HANDSHAKE_CLIENT || oc.getLocalOperationCode() == OC_DTLS_HANDSHAKE_SERVER)
                                && SS7FirewallConfig.dtls_encryption.equals("true")) {

                                    // Drop DTLS results
                                    return;       
                            }

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

                                        // Capabilities
                                        // TODO
                                        Parameter p1 = params[0];

                                        // GT prefix
                                        Parameter p2 = params[1];
                                        byte[] d2 = p2.getData();
                                        String called_gt = new String(d2);

                                        // Public key type
                                        Parameter p3 = params[2];
                                        byte[] d3 = p3.getData();
                                        String publicKeyType = new String(d3);                       

                                        // Public key
                                        Parameter p4 = params[3];
                                        byte[] d4 = p4.getData();
                                        // TODO add method into config to add public key
                                        byte[] publicKeyBytes =  d4;
                                        try {
                                            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                                            PublicKey publicKey;
                                            publicKey = keyFactoryRSA.generatePublic(pubKeySpec);
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

                // -------------- Externel Firewall rules -----------------
                if (externalFirewallRules.ss7FirewallRules(message) == false) {
                    firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "SS7 FW: Match with Externel Firewall rules", lua_hmap);
                    return;
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
                        erd = ((SccpMessageImpl)message).encode(SS7Firewall.sccpStack, lmrt, mup.getMaxUserDataLength(dpc), logger, SS7Firewall.sccpStack.isRemoveSpc(),
                                SS7Firewall.sccpStack.getSccpProtocolVersion());
                        if(connectorIDS.evalSCCPMessage(DatatypeConverter.printHexBinary(erd.getSolidData())) == false) {
                            firewallMessage(mup, mupReturn, opc, dpc, sls, ni, lmrt, message, "MAP FW:  Blocked by IDS", lua_hmap);
                            return;
                        }
                    } catch (ParseException ex) {
                        java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
                // ------------------------------------------

                
                // ------------ TCAP encryption -------------
                boolean signing_required = true;
                if (message.getCalledPartyAddress() != null && message.getCalledPartyAddress().getGlobalTitle() != null) {
                    // DTLS encryption
                    if (dtls_engine_permanent_client.containsKey(getGTPrefix(message.getCalledPartyAddress().getGlobalTitle().getDigits()))) {

                        AbstractMap.SimpleEntry<SccpDataMessage, LongMessageRuleType> p = ss7DTLSEncrypt(message, dtls_engine_permanent_client.get(getGTPrefix(message.getCalledPartyAddress().getGlobalTitle().getDigits())), lmrt);
                        
                        SccpDataMessage m = p.getKey();
                        lmrt = p.getValue();
                            
                        // not needed to sign the DLTS encrypted messages
                        signing_required = false;
                        // unable to encrypt, better drop the DTLS engine
                        if (m == null) {
                            // expire session, should trigger new DTLS handshake
                            dtls_engine_expiring_client.remove(getGTPrefix(message.getCalledPartyAddress().getGlobalTitle().getDigits()));
                        }

                        message = m;
                    }
                     // Asymmetric encryption
                    else if (SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.called_gt_encryption, message.getCalledPartyAddress().getGlobalTitle().getDigits())) {
                        PublicKey publicKey = SS7FirewallConfig.simpleWildcardFind(SS7FirewallConfig.called_gt_encryption, message.getCalledPartyAddress().getGlobalTitle().getDigits());
                        if (publicKey != null) {
                            AbstractMap.SimpleEntry<SccpDataMessage, LongMessageRuleType> p = crypto.tcapEncrypt(message, sccpMessageFactory, publicKey, lmrt);
                            message = p.getKey();
                            lmrt = p.getValue();
                        }
                    }
                }
                // --------------- TCAP signing ---------------
                if (signing_required && tag == TCBeginMessage._TAG) {
                    KeyPair keyPair = SS7FirewallConfig.simpleWildcardFind(SS7FirewallConfig.calling_gt_signing, message.getCallingPartyAddress().getGlobalTitle().getDigits());
                    if (keyPair != null) {
                        lmrt = crypto.tcapSign(message, tcb, comps, lmrt, keyPair);
                    }
                }
                // --------------------------------------------

                
                if (message.getCalledPartyAddress() != null && message.getCalledPartyAddress().getGlobalTitle() != null) {
                    // ------------ DTLS Encryption client handshake initialization ------------ 
                    if (SS7FirewallConfig.dtls_encryption.equals("true")
                            &&
                            // If not encrypted Requests towards non HPLMN
                            (tag == TCBeginMessage._TAG
                            && !SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.hplmn_gt, message.getCalledPartyAddress().getGlobalTitle().getDigits())
                            && SS7FirewallConfig.simpleWildcardCheck(SS7FirewallConfig.hplmn_gt, message.getCallingPartyAddress().getGlobalTitle().getDigits()))
                     ) {

                        String _called_gt = message.getCalledPartyAddress().getGlobalTitle().getDigits();

                        // ------------ DTLS Encryption client handshake initialization ------------ 
                        if (!dtls_handshake_timer.containsKey(_called_gt)) {

                            if(!dtls_engine_expiring_client.containsKey(getGTPrefix(_called_gt)) && !dtls_engine_handshaking_client.containsKey(getGTPrefix(_called_gt))) {

                                try {

                                    logger.info("Initiate DTLS handshake client side for GT: " + _called_gt);

                                    final String called_gt = String.valueOf(_called_gt);

                                    final Mtp3UserPart m = mup;

                                    Thread t = new Thread(new Runnable() {
                                        @Override
                                        public void run() {
                                            try {

                                                dtls_engine_handshaking_client.put(getGTPrefix(called_gt), dtls_createSSLEngine(true));

                                                // Create socket if does not exists
                                                if (!datagramOverSS7Socket_inbound_client.containsKey(getGTPrefix(called_gt))) {
                                                    datagramOverSS7Socket_inbound_client.put(getGTPrefix(called_gt), new ConcurrentLinkedQueue<DatagramOverSS7Packet>());
                                                }

                                                dtls_handshake(dtls_engine_handshaking_client.get(getGTPrefix(called_gt)), datagramOverSS7Socket_inbound_client.get(getGTPrefix(called_gt)), m, dpc, opc, sls, ni, called_gt, "client", true);
                                            } catch (Exception ex) {
                                                java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                                            }
                                        }
                                    });
                                    t.start();


                                } catch (Exception ex) {
                                    java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
                                }

                                logger.debug("dtls_sessions_reverse.put " + _called_gt + " " + null);
                                dtls_handshake_timer.put(_called_gt, null);

                            }
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

                            // to this as soon as possible to prevent concurrent threads to duplicate the autodiscovery
                            encryption_autodiscovery_sessions.put(message.getCalledPartyAddress().getGlobalTitle().getDigits().substring(0, Math.min(encryption_autodiscovery_digits, message.getCallingPartyAddress().getGlobalTitle().getDigits().length())), Utils.decodeTransactionId(otid));

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
                            SccpDataMessage m = SS7Firewall.sccpMessageFactory.createDataMessageClass0(message.getCalledPartyAddress(), message.getCallingPartyAddress(), message.getData(), message.getOriginLocalSsn(), false, null, null);
                            m.setData(_d);

                            // --------- Add also TCAP signature ------------
                            KeyPair keyPair = SS7FirewallConfig.simpleWildcardFind(SS7FirewallConfig.calling_gt_signing, message.getCallingPartyAddress().getGlobalTitle().getDigits());
                            if (keyPair != null) {
                                lmrt = crypto.tcapSign(m, t, c, lmrt, keyPair);
                            }
                            // ----------------------------------------------

                            logger.info("============ Sending Autodiscovery Invoke ============ ");

                            // Use XUDT if required
                            if (m.getData().length >= 240) {
                                l = LongMessageRuleType.XUDT_ENABLED;
                            }
                            sendSccpMessage(mup, opc, dpc, sls, ni, l, m);

                        }
                        // ---------- Encryption Autodiscovery End ---------- 
                    }
                }
                // ------------------------------------------

                logger.debug("============ Forwarding Message ============ ");
                // Use XUDT if required
                if (message.getData().length >= 240) {
                    lmrt = LongMessageRuleType.XUDT_ENABLED;
                    SccpDataMessage m = SS7Firewall.sccpMessageFactory.createDataMessageClass0(message.getCalledPartyAddress(), message.getCallingPartyAddress(), message.getData(), message.getOriginLocalSsn(), false, null, null);
                    message = m;
                }
                sendSccpMessage(mup, opc, dpc, sls, ni, lmrt, message);
            }
        });
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
        
        //logger.setLevel(org.apache.log4j.Level.DEBUG);
        
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

        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setIncludeCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        sslContextFactory.setIncludeProtocols("TLSv1.2");
        sslContextFactory.setKeyStorePath("ss7fw_keystore");
        sslContextFactory.setKeyStorePassword("BkgcNSrVn4wQWNpEowoHeHxgZeSn5WV7");
        sslContextFactory.setKeyManagerPassword("BkgcNSrVn4wQWNpEowoHeHxgZeSn5WV7");
        sslContextFactory.setSniRequired(false);

        
        HttpConfiguration https_config = new HttpConfiguration(http_config);
        SecureRequestCustomizer src = new SecureRequestCustomizer(false);
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
     * Get DTSL context
     */
    SSLContext dtls_getDTLSContext() throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        KeyStore ts = KeyStore.getInstance("JKS");

        char[] passphrase = dtls_passwd.toCharArray();

        try (FileInputStream fis = new FileInputStream(dtls_keyFilename)) {
            ks.load(fis, passphrase);
        }

        try (FileInputStream fis = new FileInputStream(dtls_trustFilename)) {
            ts.load(fis, passphrase);
        }

        kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, passphrase);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);

        SSLContext sslCtx = SSLContext.getInstance("DTLS");

        
        TrustManager tm = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };
        
        //sslCtx.init(kmf.getKeyManagers(), /*tmf.getTrustManagers()*/new TrustManager[] { tm }, /*null*/new java.security.SecureRandom());
        sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new java.security.SecureRandom());

        return sslCtx;
    }
    /**
     * Create engine for DTLS operations
     */
    SSLEngine dtls_createSSLEngine(boolean isClient) throws Exception {
        SSLContext context = dtls_getDTLSContext();
        SSLEngine engine = context.createSSLEngine();

        SSLParameters paras = engine.getSSLParameters();
        paras.setMaximumPacketSize(DTLS_MAXIMUM_PACKET_SIZE);

        engine.setUseClientMode(isClient);
        engine.setSSLParameters(paras);
        
        // Server requests client certificate authentication
        if (!isClient) {
            engine.setNeedClientAuth(true);
        }

        return engine;
    }
    
    /**
     * DTLS retransmission if timeout
     */
    boolean dtls_onReceiveTimeout(SSLEngine engine, /*SocketAddress socketAddr,*/ String peer_realm, 
            String side, List<DatagramOverSS7Packet> packets) throws Exception {

        SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
        if (hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            return false;
        } else {
            // retransmission of handshake messages
            return dtls_produceHandshakePackets(engine, peer_realm, side, packets);
        }
    }
    
    /**
     * DTLS handshake
     */
    void dtls_handshake(SSLEngine engine, 
            /*DatagramSocket socket,*/
            ConcurrentLinkedQueue<DatagramOverSS7Packet> datagramOverSS7Socket_in, 
            //ConcurrentLinkedQueue<DatagramOverSS7Packet> datagramOverSS7Socket_out,
            Mtp3UserPart mup, 
            int dpc, 
            int opc, 
            int sls, 
            int ni,
            /*SocketAddress peerAddr,*/
            String peer_gt,
            String side,
            boolean forwardIndicator) throws Exception {

        long _t = System.currentTimeMillis();
        long _end = _t + DTLS_MAX_HANDSHAKE_DURATION*1000;
        
        boolean endLoops = false;
        int loops = DTLS_MAX_HANDSHAKE_LOOPS;
        
        engine.beginHandshake();
        
        while (!endLoops && System.currentTimeMillis() < _end/*&&
                (dtls_serverException == null) && (dtls_clientException == null)*/) {

            if (--loops < 0) {
                throw new RuntimeException(
                        "Too much loops to produce handshake packets");
            }

            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            logger.info("DTLS " + side + "=======handshake(" + loops + ", " + hs + ")=======");
            if (hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP ||
                hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {

                logger.debug("DTLS " + side + ": " + "Receive DTLS records, handshake status is " + hs);

                ByteBuffer iNet;
                ByteBuffer iApp;
                if (hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                    byte[] buf = new byte[DTLS_BUFFER_SIZE];
                    DatagramOverSS7Packet packet;// = new DatagramOverSS7Packet( peer_realm, new DatagramPacket(buf, buf.length));
                    
                    //try {
                        //socket.receive(packet);
                    long t = System.currentTimeMillis();
                    long end = t + DTLS_SOCKET_TIMEOUT;
                    while(datagramOverSS7Socket_in.isEmpty() && System.currentTimeMillis() < end) {
                        Thread.sleep(DTLS_SOCKET_THREAD_SLEEP);
                    }
                    packet = datagramOverSS7Socket_in.poll();
                    
                    //} catch (SocketTimeoutException ste) {
                    if (packet == null) {
                        //log(side, "Warning: " + ste);
                        logger.warn("DTLS " + side + ": " + "Warning: DTLS_SOCKET_TIMEOUT " + DTLS_SOCKET_TIMEOUT);

                        List<DatagramOverSS7Packet> packets = new ArrayList<>();
                        boolean hasFinished = dtls_onReceiveTimeout(engine, peer_gt, side, packets);

                        logger.debug("DTLS " + side + ": " + "Reproduced " + packets.size() + " packets");
                        for (DatagramOverSS7Packet p : packets) {
                            //printHex("Reproduced packet", p.getP().getData(), p.getP().getOffset(), p.getP().getLength());
                            
                            //socket.send(p);
                            //datagramOverSS7Socket_out.add(p);
                            
                            // initiate SS7 message
                            dtls_sendDatagramOverSS7(mup, dpc, opc, sls, ni, peer_gt, p, side, forwardIndicator);
                            
                        }

                        if (hasFinished) {
                            logger.debug("DTLS " + side + ": " + "Handshake status is FINISHED "
                                    + "after calling onReceiveTimeout(), "
                                    + "finish the loop");
                            endLoops = true;
                        }

                        logger.debug("DTLS " + side + ": " + "New handshake status is "
                                + engine.getHandshakeStatus());

                        continue;
                    }

                    //printHex("Poll packet", packet.getP().getData(), packet.getP().getOffset(), packet.getP().getLength());
                            
                    logger.info("dtls_handshake: Read packet from datagramOverSS7Socket_in");
                    iNet = ByteBuffer.wrap(packet.getP().getData(), 0, packet.getP().getLength());
                    iApp = ByteBuffer.allocate(DTLS_BUFFER_SIZE);                  
                } else {
                    iNet = ByteBuffer.allocate(0);
                    iApp = ByteBuffer.allocate(DTLS_BUFFER_SIZE);
                }

                SSLEngineResult r = engine.unwrap(iNet, iApp);
                SSLEngineResult.Status rs = r.getStatus();
                hs = r.getHandshakeStatus();
                if (rs == SSLEngineResult.Status.OK) {
                    // OK
                } else if (rs == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                    logger.debug("DTLS " + side + ": " + "BUFFER_OVERFLOW, handshake status is " + hs);

                    // the client maximum fragment size config does not work?
                    throw new Exception("Buffer overflow: " +
                        "incorrect client maximum fragment size");
                } else if (rs == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                    logger.debug("DTLS " + side + ": " + "BUFFER_UNDERFLOW, handshake status is " + hs);

                    // bad packet, or the client maximum fragment size
                    // config does not work?
                    if (hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                        throw new Exception("Buffer underflow: " +
                            "incorrect client maximum fragment size");
                    } // otherwise, ignore this packet
                } else if (rs == SSLEngineResult.Status.CLOSED) {
                    throw new Exception(
                            "SSL engine closed, handshake status is " + hs);
                } else {
                    throw new Exception("Can't reach here, result is " + rs);
                }

                if (hs == SSLEngineResult.HandshakeStatus.FINISHED) {
                    logger.debug("DTLS " + side + ": " + "Handshake status is FINISHED, finish the loop");
                    endLoops = true;
                }
            } else if (hs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                List<DatagramOverSS7Packet> packets = new ArrayList<>();
                boolean hasFinished = dtls_produceHandshakePackets(
                    engine, /*peerAddr,*/ peer_gt, side, packets);

                logger.debug("DTLS " + side + ": " + "Produced " + packets.size() + " packets");
                for (DatagramOverSS7Packet p : packets) {
                    //socket.send(p);
                    
                    
                    //datagramOverSS7Socket_out.add(p);
                    // forward message
                    dtls_sendDatagramOverSS7(mup, dpc, opc, sls, ni, peer_gt, p, side, forwardIndicator);                                
                    
                }

                if (hasFinished) {
                    logger.debug("DTLS " + side + ": " + "Handshake status is FINISHED "
                            + "after producing handshake packets, "
                            + "finish the loop");
                    endLoops = true;
                }
            } else if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                dtls_runDelegatedTasks(engine);
            } else if (hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                logger.debug("DTLS " + side + ": " +
                    "Handshake status is NOT_HANDSHAKING, finish the loop");
                endLoops = true;
            } else if (hs == SSLEngineResult.HandshakeStatus.FINISHED) {
                throw new Exception(
                        "Unexpected status, SSLEngine.getHandshakeStatus() "
                                + "shouldn't return FINISHED");
            } else {
                throw new Exception(
                        "Can't reach here, handshake status is " + hs);
            }
        }

        SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
        logger.debug("DTLS " + side + ": " + "Handshake finished, status is " + hs);

        if (engine.getHandshakeSession() != null) {
            throw new Exception(
                    "Handshake finished, but handshake session is not null");
        }

        SSLSession session = engine.getSession();
        if (session == null) {
            throw new Exception("Handshake finished, but session is null");
        }
        logger.info("DTLS " + side + ": " + "Negotiated protocol is " + session.getProtocol());
        logger.info("DTLS " + side + ": " + "Negotiated cipher suite is " + session.getCipherSuite());
        
        // store SSL engine only if some cipher is negotiated
        if (!session.getProtocol().equals("NONE") && !session.getCipherSuite().equals("SSL_NULL_WITH_NULL_NULL")) {
            if (side.equals("client")) {
                dtls_engine_permanent_client.put(getGTPrefix(peer_gt), engine);
                dtls_engine_expiring_client.put(getGTPrefix(peer_gt), engine);
                dtls_engine_handshaking_client.remove(getGTPrefix(peer_gt));
                datagramOverSS7Socket_inbound_client.remove(getGTPrefix(peer_gt));
            } else if (side.equals("server")) {
                dtls_engine_permanent_server.put(getGTPrefix(peer_gt), engine);
                dtls_engine_expiring_server.put(getGTPrefix(peer_gt), engine);
                dtls_engine_handshaking_server.remove(getGTPrefix(peer_gt));
                datagramOverSS7Socket_inbound_server.remove(getGTPrefix(peer_gt));
            }  else {
                logger.error("dtls_handshake: Not client and not server side.");
            }
            
            logger.info("DTLS " + side + ": " + "Storing the SSLengine for peer: " + peer_gt);
        }
        

        // handshake status should be NOT_HANDSHAKING
        //
        // According to the spec, SSLEngine.getHandshakeStatus() can't
        // return FINISHED.
        if (hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            throw new Exception("Unexpected handshake status " + hs);
        }
    }
    
    /**
     * DTLS produce handshake packets
     */
    boolean dtls_produceHandshakePackets(SSLEngine engine, /*SocketAddress socketAddr,*/ String peer_realm,
            String side, List<DatagramOverSS7Packet> packets) throws Exception {

        long _t = System.currentTimeMillis();
        long _end = _t + DTLS_MAX_HANDSHAKE_DURATION*1000;

        boolean endLoops = false;
        int loops = DTLS_MAX_HANDSHAKE_LOOPS / 2;
        while (!endLoops && System.currentTimeMillis() < _end/*&&
                (dtls_serverException == null) && (dtls_clientException == null)*/) {

            if (--loops < 0) {
                throw new RuntimeException(
                        "Too much loops to produce handshake packets");
            }

            ByteBuffer oNet = ByteBuffer.allocate(DTLS_BUFFER_SIZE);
            ByteBuffer oApp = ByteBuffer.allocate(0);
            SSLEngineResult r = engine.wrap(oApp, oNet);
            oNet.flip();

            SSLEngineResult.Status rs = r.getStatus();
            SSLEngineResult.HandshakeStatus hs = r.getHandshakeStatus();
            logger.debug("DTLS " + side + ": " + "----produce handshake packet(" +
                    loops + ", " + rs + ", " + hs + ")----");
            if (rs == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                // the client maximum fragment size config does not work?
                throw new Exception("Buffer overflow: " +
                            "incorrect server maximum fragment size");
            } else if (rs == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                logger.debug("DTLS " + side + ": " +
                        "Produce handshake packets: BUFFER_UNDERFLOW occured");
                logger.debug("DTLS " + side + ": " +
                        "Produce handshake packets: Handshake status: " + hs);
                // bad packet, or the client maximum fragment size
                // config does not work?
                if (hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                    throw new Exception("Buffer underflow: " +
                            "incorrect server maximum fragment size");
                } // otherwise, ignore this packet
            } else if (rs == SSLEngineResult.Status.CLOSED) {
                throw new Exception("SSLEngine has closed");
            } else if (rs == SSLEngineResult.Status.OK) {
                // OK
            } else {
                throw new Exception("Can't reach here, result is " + rs);
            }

            // SSLEngineResult.Status.OK:
            if (oNet.hasRemaining()) {
                byte[] ba = new byte[oNet.remaining()];
                oNet.get(ba);
                DatagramOverSS7Packet packet = createHandshakePacket(ba, peer_realm);
                packets.add(packet);
            }

            if (hs == SSLEngineResult.HandshakeStatus.FINISHED) {
                logger.debug("DTLS " + side + ": " + "Produce handshake packets: "
                            + "Handshake status is FINISHED, finish the loop");
                return true;
            }

            boolean endInnerLoop = false;
            SSLEngineResult.HandshakeStatus nhs = hs;
            while (!endInnerLoop) {
                if (nhs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    dtls_runDelegatedTasks(engine);
                } else if (nhs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP ||
                    nhs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN ||
                    nhs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

                    endInnerLoop = true;
                    endLoops = true;
                } else if (nhs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    endInnerLoop = true;
                } else if (nhs == SSLEngineResult.HandshakeStatus.FINISHED) {
                    throw new Exception(
                            "Unexpected status, SSLEngine.getHandshakeStatus() "
                                    + "shouldn't return FINISHED");
                } else {
                    throw new Exception("Can't reach here, handshake status is "
                            + nhs);
                }
                nhs = engine.getHandshakeStatus();
            }
        }

        return false;
    }

    /**
     * DTLS createHandshakePacket
     */
    DatagramOverSS7Packet createHandshakePacket(byte[] ba, /*SocketAddress socketAddr*/ String peer_realm) {
        return new DatagramOverSS7Packet(peer_realm, new DatagramPacket(ba, ba.length));
    }
    
    /**
     * DTLS run delegated tasks
     */
    void dtls_runDelegatedTasks(SSLEngine engine) throws Exception {
        Runnable runnable;
        while ((runnable = engine.getDelegatedTask()) != null) {
            runnable.run();
        }

        SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
        if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            throw new Exception("handshake shouldn't need additional tasks");
        }
    }
    
    void dtls_sendDatagramOverSS7(Mtp3UserPart mup, int dpc, int opc, int sls, int ni, String _peer_gt, DatagramOverSS7Packet p, String side, boolean forwardIndicator) {
        
        LongMessageRuleType lmrt = LongMessageRuleType.XUDT_ENABLED;
        GlobalTitle callingGT = SS7Firewall.sccpProvider.getParameterFactory().createGlobalTitle(SS7FirewallConfig.fw_gt.firstKey(), 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_MOBILE, null, NatureOfAddress.INTERNATIONAL);
        GlobalTitle calledGT = SS7Firewall.sccpProvider.getParameterFactory().createGlobalTitle(_peer_gt, 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_MOBILE, null, NatureOfAddress.INTERNATIONAL);
        SccpAddress callingParty = SS7Firewall.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, callingGT, 1, 8);
        SccpAddress calledParty = SS7Firewall.sccpProvider.getParameterFactory().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, calledGT, 2, 8);
        
        byte[] data = {0};
        SccpDataMessage message = SS7Firewall.sccpMessageFactory.createDataMessageClass0(calledParty, callingParty, data, 8, false, null, null);
                    
        
        TCBeginMessage t = TcapFactory.createTCBeginMessage();


        byte[] otid = { (byte)randomGenerator.nextInt(256), (byte)randomGenerator.nextInt(256), (byte)randomGenerator.nextInt(256), (byte)randomGenerator.nextInt(256) };

        // to this as soon as possible to prevent concurrent threads to duplicate the autodiscovery
        encryption_autodiscovery_sessions.put(message.getCalledPartyAddress().getGlobalTitle().getDigits().substring(0, Math.min(encryption_autodiscovery_digits, message.getCallingPartyAddress().getGlobalTitle().getDigits().length())), Utils.decodeTransactionId(otid));

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
        if (side.equals("client")) {
            oc.setLocalOperationCode(OC_DTLS_HANDSHAKE_CLIENT);
        } else if (side.equals("server")) {
            oc.setLocalOperationCode(OC_DTLS_HANDSHAKE_SERVER);
        } else {
            logger.error("dtls_sendDatagramOverSS7: Not client and not server side.");
            return;
        }
        ((InvokeImpl)c[0]).setOperationCode(oc);
        
        // DATA
        Parameter p1 = TcapFactory.createParameter();
        p1.setTagClass(Tag.CLASS_PRIVATE);
        p1.setPrimitive(true);
        p1.setTag(Tag.STRING_OCTET);
        p1.setData(p.getP().getData());

        // DTLS data
        Parameter _p = TcapFactory.createParameter();
        _p.setTagClass(Tag.CLASS_UNIVERSAL);
        _p.setTag(0x04);
        _p.setParameters(new Parameter[] { p1 });
        ((InvokeImpl)c[0]).setParameter(_p);

        t.setComponent(c);
        AsnOutputStream aos = new AsnOutputStream();
        try {
            t.encode(aos);
        } catch (EncodeException ex) {
            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }

        byte[] _d = aos.toByteArray();

        LongMessageRuleType l = lmrt;
        SccpDataMessage m = SS7Firewall.sccpMessageFactory.createDataMessageClass0(message.getCalledPartyAddress(), message.getCallingPartyAddress(), message.getData(), message.getOriginLocalSsn(), false, null, null);
        m.setData(_d);

        logger.info("============ Sending DTLS ============ ");

        // Use XUDT if required
        if (m.getData().length >= 240) {
            l = LongMessageRuleType.XUDT_ENABLED;
        }
        sendSccpMessage(mup, opc, dpc, sls, ni, l, m);
          
    }
    
    
    /**
     * DTLS encrypt byte buffer
     */
    boolean ss7DTLSEncryptBuffer(SSLEngine engine, ByteBuffer source, ByteBuffer appNet) throws Exception {

        //printHex("Received application data for Encrypt", source);
        
        List<DatagramPacket> packets = new ArrayList<>();
        SSLEngineResult r = engine.wrap(source, appNet);
        appNet.flip();

        SSLEngineResult.Status rs = r.getStatus();
        if (rs == SSLEngineResult.Status.BUFFER_OVERFLOW) {
            // the client maximum fragment size config does not work?
            logger.warn("Buffer overflow: " + "incorrect server maximum fragment size");
            return false;
        } else if (rs == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
            // unlikely
            logger.warn("Buffer underflow during wraping");
            return false;
        } else if (rs == SSLEngineResult.Status.CLOSED) {
            logger.warn("SSLEngine has closed");
            return false;
        } else if (rs == SSLEngineResult.Status.OK) {
            // OK
        } else {
            logger.warn("Can't reach here, result is " + rs);
            return false;
        }

        // SSLEngineResult.Status.OK:
        // printHex("Produced application data by Encrypt", appNet);
        return true;
    }
    
    /**
     * DTLS decrypt byte buffer
     */
    boolean ss7DTLSDecryptBuffer(SSLEngine engine, ByteBuffer source, ByteBuffer recBuffer) throws Exception {
     
        //printHex("Received application data for Decrypt", source);
        
        SSLEngineResult r = engine.unwrap(source, recBuffer);
        recBuffer.flip();
        
        SSLEngineResult.Status rs = r.getStatus();
        if (rs == SSLEngineResult.Status.BUFFER_OVERFLOW) {
            // the client maximum fragment size config does not work?
            logger.warn("Buffer overflow: " + "incorrect server maximum fragment size");
            return false;
        } else if (rs == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
            // unlikely
            logger.warn("Buffer underflow during wraping");
            return false;
        } else if (rs == SSLEngineResult.Status.CLOSED) {
            logger.warn("SSLEngine has closed");
            return false;
        } else if (rs == SSLEngineResult.Status.OK) {
            // OK
        } else {
            logger.warn("Can't reach here, result is " + rs);
            return false;
        }
        
        //printHex("Produced application data by Decrypt", recBuffer);
        return true;
    }
     
    /**
     * DTLS encrypt
     * @param message
     * @param engine
     * @param lmrt Long Message Rule Type, if UDT or XUDT should be send
     * @return AbstractMap.SimpleEntry<message, lmrt> - message and indicator if UDT or XUDT should be send
     */
    public AbstractMap.SimpleEntry<SccpDataMessage, LongMessageRuleType> ss7DTLSEncrypt(SccpDataMessage message, SSLEngine engine, LongMessageRuleType lmrt) {
        
        logger.debug("== ss7DTLSEncrypt ==");
        
        LongMessageRuleType l = lmrt;
        
        try {
            
            // Sending XUDT message from UDT message
            
            byte [] d = message.getData();

            logger.debug("plainText = " + d.toString());
            logger.debug("plainText.size = " + d.length);
            
            /*// SPI(version) and TVP(timestamp)
            byte[] SPI = {0x00, 0x00, 0x00, 0x00};  // TODO
            byte[] TVP = {0x00, 0x00, 0x00, 0x00};

            long t = System.currentTimeMillis()/100;    // in 0.1s
            TVP[0] = (byte) ((t >> 24) & 0xFF);
            TVP[1] = (byte) ((t >> 16) & 0xFF);
            TVP[2] = (byte) ((t >>  8) & 0xFF);
            TVP[3] = (byte) ((t >>  0) & 0xFF);*/
            
            ByteBuffer cipherTextBuffer = ByteBuffer.allocate(DTLS_BUFFER_SIZE);
            boolean res = ss7DTLSEncryptBuffer(engine, ByteBuffer.wrap(d, 0, d.length), cipherTextBuffer);
            if (res == false) {
                logger.warn("diameterDTLSEncrypt: Failed encryption of DTLS data");
                return null;
            }
            
            byte[] cipherText = new byte[cipherTextBuffer.remaining()];
            cipherTextBuffer.get(cipherText);
            
            TCBeginMessage tc = TcapFactory.createTCBeginMessage();

            byte[] otid = { (byte)randomGenerator.nextInt(256), (byte)randomGenerator.nextInt(256), (byte)randomGenerator.nextInt(256), (byte)randomGenerator.nextInt(256) };

            tc.setOriginatingTransactionId(otid);
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

            tc.setDialogPortion(dp);

            Component[] c = new Component[1];

            c[0] = new InvokeImpl();
            ((InvokeImpl)c[0]).setInvokeId(1l);
            OperationCode oc = TcapFactory.createOperationCode();
            oc.setLocalOperationCode(OC_DTLS_DATA);
            ((InvokeImpl)c[0]).setOperationCode(oc);

            // DATA
            Parameter p1 = TcapFactory.createParameter();
            p1.setTagClass(Tag.CLASS_PRIVATE);
            p1.setPrimitive(true);
            p1.setTag(Tag.STRING_OCTET);
            p1.setData(cipherText);

            // Encrypted data
            Parameter _p = TcapFactory.createParameter();
            _p.setTagClass(Tag.CLASS_UNIVERSAL);
            _p.setTag(0x04);
            _p.setParameters(new Parameter[] { p1 });
            ((InvokeImpl)c[0]).setParameter(_p);

            tc.setComponent(c);
            AsnOutputStream aos = new AsnOutputStream();
            try {
                tc.encode(aos);
            } catch (EncodeException ex) {
                java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
            }

            byte[] _d = aos.toByteArray();

            
            SccpDataMessage m = sccpMessageFactory.createDataMessageClass0(message.getCalledPartyAddress(), message.getCallingPartyAddress(), _d, message.getOriginLocalSsn(), false, null, null);
            l = LongMessageRuleType.XUDT_ENABLED;
            return new AbstractMap.SimpleEntry<>(m, l);
                

        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return null;
    }

    
    /**
     * DTLS decrypt
     * @param message
     * @param comps TCAP components
     * @param engine
     * @return AbstractMap.SimpleEntry<message, result> - message and result indicator
     */
    public AbstractMap.SimpleEntry<SccpDataMessage, String> ss7DTLSDecrypt(SccpDataMessage message, Component[] comps, SSLEngine engine) {
        
        logger.debug("== ss7DTLSDecrypt ==");
            
        try {
            byte[] data = message.getData();
            
            AsnInputStream ais = new AsnInputStream(data);
            
            // this should have TC message tag
            int tag;
            try {
                tag = ais.readTag();
            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                logger.warn("Unknown TCAP tag detected in tcapDecrypt");
                return new AbstractMap.SimpleEntry<>(message, "Unknown TCAP tag detected in tcapDecrypt");
            }
            
            byte[] message_data = null;
                
            for (Component comp : comps) {
                if (comp == null) {
                    continue;
                }

                OperationCodeImpl oc;

                switch (comp.getType()) {
                case Invoke:
                    Invoke inv = (Invoke) comp;
                       
                    Parameter p = inv.getParameter();
                    Parameter[] params = p.getParameters();
                    
                    if (params != null && params.length >= 1) {

                        // Encrypted data
                        Parameter p1 = params[0];
                        message_data = p1.getData();
                    }
                break;
                }
            }
            byte[] d = message_data;
            
            ByteBuffer decryptedTextBuffer = ByteBuffer.allocate(DTLS_BUFFER_SIZE);
            boolean res = ss7DTLSDecryptBuffer(engine, ByteBuffer.wrap(d, 0, d.length), decryptedTextBuffer);
            if (res == false) {
                logger.warn("ss7DTLSDecrypt: Failed decryption of DTLS data");
                return new AbstractMap.SimpleEntry<>(message, "Failed decryption of DTLS data");
            }


            if (decryptedTextBuffer.remaining() != 0) {
                logger.debug("ss7DTLSDecrypt: Successful decryption of DTLS data");
            }

            byte[] decryptedText = new byte[decryptedTextBuffer.remaining()];
            decryptedTextBuffer.get(decryptedText);
            
            SccpDataMessage m = sccpMessageFactory.createDataMessageClass0(message.getCalledPartyAddress(), message.getCallingPartyAddress(), decryptedText, message.getOriginLocalSsn(), false, null, null);
            
            return new AbstractMap.SimpleEntry<>(m, "");

        } catch (Exception ex) {
            java.util.logging.Logger.getLogger(SS7Firewall.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return new AbstractMap.SimpleEntry<>(message, "Failed decryption of DTLS data");
    }

    /**
     * getGTPrefix
     * @param gt
     * @return gt_prefix
     */
    public String getGTPrefix(String gt) {
        if (gt == null) {
            return null;
        }
        return gt.substring(0, Math.min(gt.length(), 5));
    }
}
