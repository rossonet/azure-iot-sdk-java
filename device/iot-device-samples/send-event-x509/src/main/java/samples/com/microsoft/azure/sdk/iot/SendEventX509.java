// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

package samples.com.microsoft.azure.sdk.iot;

import com.microsoft.azure.sdk.iot.device.*;
import com.microsoft.azure.sdk.iot.provisioning.security.SecurityProvider;
import com.microsoft.azure.sdk.iot.provisioning.security.SecurityProviderX509;
import com.microsoft.azure.sdk.iot.provisioning.security.exceptions.SecurityProviderException;
import com.sun.xml.internal.org.jvnet.mimepull.CleanUpExecutorFactory;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.apache.commons.codec.binary.Base64.encodeBase64String;

/** Sends a number of event messages to an IoT Hub. */
public class SendEventX509
{
    static final String DEFAULT_TLS_PROTOCOL = "TLSv1.2";
    private static final String ALIAS_CERT_ALIAS = "cert-alias";
    private  static final int D2C_MESSAGE_TIMEOUT = 2000; // 2 seconds
    private  static final List<String> failedMessageListOnClose = new ArrayList<>(); // List of messages that failed on close

    protected static class EventCallback implements IotHubEventCallback
    {
        public void execute(IotHubStatusCode status, Object context)
        {
            Message msg = (Message) context;
            
            System.out.println("IoT Hub responded to message "+ msg.getMessageId()  + " with status " + status.name());
            
            if (status== IotHubStatusCode.MESSAGE_CANCELLED_ONCLOSE)
            {
                failedMessageListOnClose.add(msg.getMessageId());
            }
        }
    }

    /**
     * Sends a number of messages to an IoT Hub. Default protocol is to 
     * use MQTT transport.
     *
     * @param args
     * args[0] = IoT Hub connection string
     * args[1] = number of requests to send
     * args[2] = IoT Hub protocol to use, optional and defaults to MQTT
     */
    public static void main(String[] args) throws IOException, URISyntaxException, GeneralSecurityException, SecurityProviderException, OperatorCreationException {
        System.out.println("Starting...");
        System.out.println("Beginning setup.");
 
        if (!(args.length == 2 || args.length == 3))
        {
            System.out.format(
                    "Expected 2 or 3 arguments but received: %d.\n"
                            + "The program should be called with the following args: \n"
                            + "1. [Device connection string] - String containing Hostname, Device Id & Device Key in one of the following formats: HostName=<host_name>;DeviceId=<device_id>;x509=true\n"
                            + "2. [number of requests to send]\n"
                            + "3. (mqtt | https | amqps | amqps_ws | mqtt_ws)\n",
                    args.length);
            return;
        }

        String connectionString = args[0];

        int numRequests;
        try
        {
            numRequests = Integer.parseInt(args[1]);
        }
        catch (NumberFormatException e)
        {
            System.out.format(
                    "Could not parse the number of requests to send. "
                            + "Expected an int but received:\n%s.\n", args[1]);
            return;
        }

        IotHubClientProtocol protocol;
        if (args.length == 2)
        {
            protocol = IotHubClientProtocol.MQTT;
        }
        else
        {
            String protocolStr = args[2].toLowerCase();
            if (protocolStr.equals("https"))
            {
                protocol = IotHubClientProtocol.HTTPS;
            }
            else if (protocolStr.equals("amqps"))
            {
                protocol = IotHubClientProtocol.AMQPS;
            }
            else if (protocolStr.equals("mqtt"))
            {
                protocol = IotHubClientProtocol.MQTT;
            }
            else if (protocolStr.equals("mqtt_ws"))
            {
                protocol = IotHubClientProtocol.MQTT_WS;
            }
            else
            {
                System.out.format(
                        "Expected argument 3 to be one of 'mqtt', 'mqtt_ws', 'https', or 'amqps' but received %s\n"
                                + "The program should be called with the following args: \n"
                                + "1. [Device connection string] - String containing Hostname, Device Id & Device Key in one of the following formats: HostName=<host_name>;DeviceId=<device_id>;x509=true\n"
                                + "2. [number of requests to send]\n"
                                + "3. (mqtt | https | amqps | amqps_ws | mqtt_ws)\n",
                        protocolStr);
                return;
            }
        }

        System.out.println("Successfully read input parameters.");
        System.out.format("Using communication protocol %s.\n", protocol.name());

        final GeneratedCert rootCert = X509CertificateGenerator.generateCertificateWithReturn("rootCert", null);
        final GeneratedCert cert1 = X509CertificateGenerator.generateCertificateWithReturn("cert1", rootCert);
        final GeneratedCert cert2 = X509CertificateGenerator.generateCertificateWithReturn("cert2", cert1);
        final GeneratedCert deviceCert = X509CertificateGenerator.generateCertificateWithReturn("deviceCert", cert2);

        // This is the thumbprint used for device created on portal
        String thumbprint = deviceCert.x509ThumbPrint;

        Collection<X509Certificate> signerCertificates = new LinkedList<X509Certificate>()
        {
            {
                add(rootCert.certificate);
                add(cert1.certificate);
                add(cert2.certificate);
            }
        };

        // Call method that returns generatedcert and create a collection of these certs

        SSLContext sslContext = generateSSLContext(deviceCert.certificate, deviceCert.privateKey, signerCertificates);
        ClientOptions clientOptions = new ClientOptions();
        clientOptions.setSslContext(sslContext);
        DeviceClient client = new DeviceClient(connectionString, protocol, clientOptions);

        System.out.println("Successfully created an IoT Hub client.");

        client.open();

        System.out.println("Opened connection to IoT Hub.");
        System.out.println("Sending the following event messages:");

        String deviceId = "hello";
        double temperature;
        double humidity;

        for (int i = 0; i < numRequests; ++i)
        {
            temperature = 20 + Math.random() * 10;
            humidity = 30 + Math.random() * 20;

            String msgStr = "{\"deviceId\":\"" + deviceId +"\",\"messageId\":" + i + ",\"temperature\":"+ temperature +",\"humidity\":"+ humidity +"}";
            
            try
            {
                Message msg = new Message(msgStr);
                msg.setContentTypeFinal("application/json");
                msg.setProperty("temperatureAlert", temperature > 28 ? "true" : "false");
                msg.setMessageId(java.util.UUID.randomUUID().toString());
                msg.setExpiryTime(D2C_MESSAGE_TIMEOUT);
                System.out.println(msgStr);

                EventCallback callback = new EventCallback();
                client.sendEventAsync(msg, callback, msg);
            }
            catch (Exception e)
            {
                 e.printStackTrace();
            }
        }
        
        System.out.println("Wait for " + D2C_MESSAGE_TIMEOUT / 1000 + " second(s) for response from the IoT Hub...");
        
        // Wait for IoT Hub to respond.
        try
        {
          Thread.sleep(D2C_MESSAGE_TIMEOUT);
        }
        catch (InterruptedException e)
        {
          e.printStackTrace();
        }

        // close the connection        
        System.out.println("Closing"); 
        client.closeNow();
        
        if (!failedMessageListOnClose.isEmpty())
        {
            System.out.println("List of messages that were cancelled on close:" + failedMessageListOnClose.toString()); 
        }

        System.out.println("Shutting down...");
    }

    public static SSLContext generateSSLContext(X509Certificate leafCertificate, Key leafPrivateKey, Collection<X509Certificate> signerCertificates) throws NoSuchProviderException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException, CertificateException, SecurityProviderException
    {
        if (leafCertificate == null || leafPrivateKey == null || signerCertificates == null)
        {
            //SRS_SecurityClientX509_25_006: [ This method shall throw IllegalArgumentException if input parameters are null. ]
            throw new IllegalArgumentException("cert or private key cannot be null");
        }

        //SRS_SecurityClientX509_25_007: [ This method shall use random UUID as a password for keystore. ]
        char[] password = SSLContextBuilder.generateTemporaryPassword();
        //SRS_SecurityClientX509_25_008: [ This method shall create a TLSv1.2 instance. ]
        SSLContext sslContext = SSLContext.getInstance(DEFAULT_TLS_PROTOCOL);
        // Load Trusted certs to keystore and retrieve it.

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        keyStore.setCertificateEntry(ALIAS_CERT_ALIAS, leafCertificate);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password);

        TrustManagerFactory trustManagerFactory = SSLContextBuilder.generateTrustManagerFactory(keyStore);

        // Load Alias cert and private key to key store
        int noOfCerts = signerCertificates.size() + 1;
        X509Certificate[] certs = new X509Certificate[noOfCerts];
        int i = 0;
        certs[i++] = leafCertificate;

        // Load the chain of signer cert to keystore
        for (X509Certificate c : signerCertificates)
        {
            certs[i++] = c;
        }
        //SRS_SecurityClientX509_25_010: [ This method shall load all the provided X509 certs (leaf with both public certificate and private key,
        // intermediate certificates(if any) to the Key store. ]
        keyStore.setKeyEntry(ALIAS_CERT_ALIAS, leafPrivateKey, password, certs);

        //SRS_SecurityClientX509_25_011: [ This method shall initialize the ssl context with X509KeyManager and X509TrustManager for the keystore. ]
        sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
        //SRS_SecurityClientX509_25_012: [ This method shall return the ssl context created as above to the caller. ]
        return sslContext;
    }
}
