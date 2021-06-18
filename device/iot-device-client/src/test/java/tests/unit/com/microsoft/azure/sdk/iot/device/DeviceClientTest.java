// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

package tests.unit.com.microsoft.azure.sdk.iot.device;

import com.microsoft.azure.sdk.iot.device.*;
import com.microsoft.azure.sdk.iot.device.DeviceTwin.PropertyCallBack;
import com.microsoft.azure.sdk.iot.device.auth.IotHubAuthenticationProvider;
import com.microsoft.azure.sdk.iot.device.auth.IotHubSasTokenAuthenticationProvider;
import com.microsoft.azure.sdk.iot.device.exceptions.DeviceClientException;
import com.microsoft.azure.sdk.iot.device.exceptions.TransportException;
import com.microsoft.azure.sdk.iot.device.fileupload.FileUploadClient;
import com.microsoft.azure.sdk.iot.device.transport.amqps.IoTHubConnectionType;
import com.microsoft.azure.sdk.iot.provisioning.security.SecurityProvider;
import com.microsoft.azure.sdk.iot.provisioning.security.exceptions.SecurityProviderException;
import mockit.*;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import java.io.IOError;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;

import static com.microsoft.azure.sdk.iot.device.transport.amqps.IoTHubConnectionType.SINGLE_CLIENT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Unit tests for DeviceClient.
 * Methods: 100%
 * Lines: 98%
 */
public class DeviceClientTest
{
    @Mocked
    DeviceClientConfig mockConfig;

    @Mocked
    IotHubConnectionString mockIotHubConnectionString;

    @Mocked
    ClientOptions mockClientOptions;

    @Mocked
    DeviceIO mockDeviceIO;

    @Mocked
    FileUploadClient mockFileUpload;

    @Mocked
    IotHubAuthenticationProvider mockIotHubAuthenticationProvider;

    @Mocked
    IotHubSasTokenAuthenticationProvider mockIotHubSasTokenAuthenticationProvider;

    @Mocked
    SecurityProvider mockSecurityProvider;

    @Mocked
    IotHubConnectionStatusChangeCallback mockedIotHubConnectionStatusChangeCallback;

    @Mocked
    ProductInfo mockedProductInfo;

    private static final long SEND_PERIOD_MILLIS = 10L;
    private static final long RECEIVE_PERIOD_MILLIS_AMQPS = 10L;
    private static final long RECEIVE_PERIOD_MILLIS_HTTPS = 25*60*1000; /*25 minutes*/

    private static final long SEND_PERIOD = 10;
    private static final long RECEIVE_PERIOD = 10;

    @Test
    public void constructorSuccess() throws URISyntaxException, IOException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;CredentialScope=Device;deviceId=testdevice;SharedAccessKey=adjkl234j52=;";
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;

        // act
        final DeviceClient client = new DeviceClient(connString, protocol, (ClientOptions) null);

        // assert
        new Verifications()
        {
            {
                Deencapsulation.newInstance(IotHubConnectionString.class, connString);
                times = 1;

                IoTHubConnectionType ioTHubConnectionType = Deencapsulation.getField(client, "ioTHubConnectionType");
                assertEquals(SINGLE_CLIENT, ioTHubConnectionType);
            }
        };
    }

    @Test
    public void constructorWithClientOptionsSuccess(@Mocked final ClientOptions mockedClientOptions) throws URISyntaxException
    {
        // arrange
        final String connString =
                "HostName=iothub.device.com;deviceId=testdevice;x509=true";
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS_WS;

        new Expectations()
        {
            {
                new IotHubConnectionString(connString);
                result = mockIotHubConnectionString;
            }
        };

        // act
        final DeviceClient client = new DeviceClient(connString, protocol, mockedClientOptions);

        // assert
        new Verifications()
        {
            {
                IoTHubConnectionType ioTHubConnectionType = Deencapsulation.getField(client, "ioTHubConnectionType");
                assertEquals(SINGLE_CLIENT, ioTHubConnectionType);

                new DeviceClientConfig(mockIotHubConnectionString, mockedClientOptions);
            }
        };
    }

    @Test
    public void constructorWithSSLContextSuccess(@Mocked final SSLContext mockedSSLContext, @Mocked final ClientOptions mockedClientOptions) throws URISyntaxException
    {
        // arrange
        final String connString =
                "HostName=iothub.device.com;deviceId=testdevice;x509=true";
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS_WS;

        new Expectations()
        {
            {
                new IotHubConnectionString(connString);
                result = mockIotHubConnectionString;
            }
        };

        new DeviceClientConfig(mockIotHubConnectionString, mockedClientOptions);

        // act
        final DeviceClient client = new DeviceClient(connString, protocol, mockedSSLContext);

        // assert
        new Verifications()
        {
            {
                IoTHubConnectionType ioTHubConnectionType = Deencapsulation.getField(client, "ioTHubConnectionType");
                assertEquals(SINGLE_CLIENT, ioTHubConnectionType);

                new DeviceClientConfig(mockIotHubConnectionString, mockedClientOptions);
            }
        };
    }

    //Tests_SRS_DEVICECLIENT_34_065: [The provided uri and device id will be used to create an iotHubConnectionString that will be saved in config.]
    //Tests_SRS_DEVICECLIENT_34_066: [The provided security provider will be saved in config.]
    //Tests_SRS_DEVICECLIENT_34_067: [The constructor shall initialize the IoT Hub transport for the protocol specified, creating a instance of the deviceIO.]
    @Test
    public void createFromSecurityProviderUsesUriAndDeviceIdAndSavesSecurityProviderAndCreatesDeviceIO() throws URISyntaxException, IOException, SecurityProviderException
    {
        //arrange
        final String expectedUri = "some uri";
        final String expectedDeviceId = "some device id";
        final IotHubClientProtocol expectedProtocol = IotHubClientProtocol.HTTPS;

        //act
        DeviceClient.createFromSecurityProvider(expectedUri, expectedDeviceId, mockSecurityProvider, expectedProtocol, null);

        //assert
        new Verifications()
        {
            {
                //TODO add check for super() call
            }
        };
    }

    /* Tests_SRS_DEVICECLIENT_21_001: [The constructor shall interpret the connection string as a set of key-value pairs delimited by ';', using the object IotHubConnectionString.] */
    @Test
    public void constructorBadConnectionStringThrows() throws URISyntaxException, IOException
    {
        // arrange
        final String connString =
                "HostName=iothub.device.com;CredentialType=SharedAccessKey;CredentialScope=Device;deviceId=testdevice;SharedAccessKey=adjkl234j52=;";
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;

        //assert
        new Expectations()
        {
            {
                Deencapsulation.newInstance(IotHubConnectionString.class, connString);
                result = new IllegalArgumentException();
            }
        };

        // act
        try
        {
            new DeviceClient(connString, protocol);
        }
        catch (IllegalArgumentException expected)
        {
            // Don't do anything, throw expected.
        }

        // assert
        new Verifications()
        {
            {
                Deencapsulation.newInstance(DeviceClientConfig.class, new Class[] {IotHubConnectionString.class}, (IotHubConnectionString) any);
                times = 0;
                Deencapsulation.newInstance("com.microsoft.azure.sdk.iot.device.DeviceIO",
                        new Class[] {DeviceClientConfig.class, long.class, long.class},
                        any, SEND_PERIOD_MILLIS, RECEIVE_PERIOD_MILLIS_AMQPS);
                times = 0;
            }
        };
    }

    /* Tests_SRS_DEVICECLIENT_21_002: [The constructor shall initialize the IoT Hub transport for the protocol specified, creating a instance of the deviceIO.] */
    @Test (expected = IllegalArgumentException.class)
    public void constructorBadDeviceIOThrows() throws URISyntaxException, IOException
    {
        // arrange
        final String connString =
                "HostName=iothub.device.com;CredentialType=SharedAccessKey;CredentialScope=Device;deviceId=testdevice;SharedAccessKey=adjkl234j52=;";
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;

        // act
        new DeviceClient(connString, protocol);

        // assert
        new Verifications()
        {
            {
                Deencapsulation.newInstance(IotHubConnectionString.class, connString);
                times = 1;
                Deencapsulation.newInstance(DeviceClientConfig.class, (IotHubConnectionString)any, DeviceClientConfig.AuthType.SAS_TOKEN);
                times = 1;
                Deencapsulation.newInstance("com.microsoft.azure.sdk.iot.device.DeviceIO",
                        new Class[] {DeviceClientConfig.class, IotHubClientProtocol.class, long.class, long.class},
                        (DeviceClientConfig)any, protocol, SEND_PERIOD_MILLIS, RECEIVE_PERIOD_MILLIS_AMQPS);
                times = 1;
            }
        };
    }

    /* Tests_SRS_DEVICECLIENT_21_003: [The constructor shall save the connection configuration using the object DeviceClientConfig.] */
    @Test (expected = IllegalArgumentException.class)
    public void constructorBadDeviceClientConfigThrows() throws URISyntaxException, IOException
    {
        // arrange
        final String connString =
                "HostName=iothub.device.com;CredentialType=SharedAccessKey;CredentialScope=Device;deviceId=testdevice;SharedAccessKey=adjkl234j52=;";
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;

        // act
        new DeviceClient(connString, protocol);

        // assert
        new Verifications()
        {
            {
                Deencapsulation.newInstance(DeviceClientConfig.class, (IotHubConnectionString)any, DeviceClientConfig.AuthType.SAS_TOKEN);
                times = 1;
                Deencapsulation.newInstance("com.microsoft.azure.sdk.iot.device.DeviceIO",
                        new Class[] {DeviceClientConfig.class, IotHubClientProtocol.class, long.class, long.class},
                        (DeviceClientConfig)any, protocol, SEND_PERIOD_MILLIS, RECEIVE_PERIOD_MILLIS_AMQPS);
                times = 0;
            }
        };
    }

    // Tests_SRS_DEVICECLIENT_21_006: [The open shall invoke super.open().]
    @Test
    public void openOpensDeviceIOSuccess(final @Mocked InternalClient mockedInternalClient) throws DeviceClientException, URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        DeviceClient client = new DeviceClient(connString, protocol);

        // act
        client.open();

        // assert
        new Verifications()
        {
            {
                Deencapsulation.invoke(mockedInternalClient, "open");
                times = 1;
            }
        };
    }

    //Tests_SRS_DEVICECLIENT_34_040: [If this object is not using a transport client, it shall invoke super.close().]
    @Test
    public void closeClosesTransportSuccess(final @Mocked InternalClient mockedInternalClient) throws DeviceClientException, URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        DeviceClient client = new DeviceClient(connString, protocol);

        // act
        client.close();

        // assert
        new Verifications()
        {
            {
                mockedInternalClient.close();
                times = 1;
            }
        };
    }

    //Tests_SRS_DEVICECLIENT_34_041: [If this object is not using a transport client, it shall invoke super.closeNow().]
    @Test
    public void closeNowClosesTransportSuccess(final @Mocked InternalClient mockedInternalClient) throws DeviceClientException, URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        DeviceClient client = new DeviceClient(connString, protocol);

        // act
        client.closeNow();

        // assert
        new Verifications()
        {
            {
                mockedInternalClient.closeNow();
                times = 1;
            }
        };
    }

    // Tests_SRS_DEVICECLIENT_02_015: [If optionName is null or not an option handled by the client, then it shall throw IllegalArgumentException.]
    @Test (expected = IllegalArgumentException.class)
    public void setOptionWithNullOptionNameThrows()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = false;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
            }
        };
        DeviceClient client = new DeviceClient(connString, protocol);

        long someMilliseconds = 4;

        // act
        client.setOption(null, someMilliseconds);
    }

    // Tests_SRS_DEVICECLIENT_02_015: [If optionName is null or not an option handled by the client, then it shall throw IllegalArgumentException.]
    @Test (expected = IllegalArgumentException.class)
    public void setOptionWithUnknownOptionNameThrows()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = false;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
            }
        };
        DeviceClient client = new DeviceClient(connString, protocol);

        long someMilliseconds = 4;

        // act
        client.setOption("thisIsNotAHandledOption", someMilliseconds);
    }

    //Tests_SRS_DEVICECLIENT_02_017: [Available for all protocols]
    @Test
    public void setOptionSetReceiveIntervalWithMQTTsucceeds()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.MQTT;
        final long someMilliseconds = 4L;
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = false;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.MQTT;
            }
        };
        DeviceClient client = new DeviceClient(connString, protocol, (ClientOptions) null);

        // act
        client.setOption("SetReceiveInterval", someMilliseconds);

        // assert
        new Verifications()
        {
            {
                mockDeviceIO.setReceivePeriodInMilliseconds(someMilliseconds);
            }
        };
    }

    //Tests_SRS_DEVICECLIENT_02_018: [Value needs to have type long].
    @Test (expected = IllegalArgumentException.class)
    public void setOptionMinimumPollingIntervalWithStringInsteadOfLongFails()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = false;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
            }
        };
        DeviceClient client = new DeviceClient(connString, protocol, (ClientOptions) null);

        // act
        client.setOption("SetMinimumPollingInterval", "thisIsNotALong");
    }

    //Tests_SRS_DEVICECLIENT_02_005: [Setting the option can only be done before open call.]
    @Test (expected = IllegalStateException.class)
    public void setOptionMinimumPollingIntervalAfterOpenFails()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = true;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
            }
        };
        DeviceClient client = new DeviceClient(connString, protocol, (ClientOptions) null);
        client.open();
        long value = 3;

        // act
        client.setOption("SetMinimumPollingInterval", value);
    }

    //Tests_SRS_DEVICECLIENT_02_016: ["SetMinimumPollingInterval" - time in milliseconds between 2 consecutive polls.]
    @Test
    public void setOptionMinimumPollingIntervalSucceeds()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = false;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
            }
        };
        DeviceClient client = new DeviceClient(connString, protocol, (ClientOptions) null);
        final long value = 3L;

        // act
        client.setOption("SetMinimumPollingInterval", value);

        // assert
        new Verifications()
        {
            {
                mockDeviceIO.setReceivePeriodInMilliseconds(value);
            }
        };
    }

    // Tests_SRS_DEVICECLIENT_21_040: ["SetSendInterval" - time in milliseconds between 2 consecutive message sends.]
    @Test
    public void setOptionSendIntervalSucceeds()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = false;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
            }
        };
        DeviceClient client = new DeviceClient(connString, protocol, (ClientOptions) null);
        final long value = 3L;

        // act
        client.setOption("SetSendInterval", value);

        // assert
        new Verifications()
        {
            {
                mockDeviceIO.setSendPeriodInMilliseconds(value);
            }
        };
    }

    @Test (expected = IllegalArgumentException.class)
    public void setOptionSendIntervalWithStringInsteadOfLongFails()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = false;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
            }
        };
        DeviceClient client = new DeviceClient(connString, protocol);

        // act
        client.setOption("SetSendInterval", "thisIsNotALong");
    }

    @Test (expected = IllegalArgumentException.class)
    public void setOptionValueNullThrows()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;
        new NonStrictExpectations()
        {
            {
                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.SAS_TOKEN;
            }
        };
        DeviceClient client = new DeviceClient(connString, protocol);

        // act
        client.setOption("", null);
    }

    //Tests_SRS_DEVICECLIENT_25_022: [**"SetSASTokenExpiryTime" should have value type long.]
    @Test (expected = IllegalArgumentException.class)
    public void setOptionSASTokenExpiryTimeWithStringInsteadOfLongFails()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;
        new NonStrictExpectations()
        {
            {
                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.SAS_TOKEN;
                mockDeviceIO.isOpen();
                result = false;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
            }
        };
        DeviceClient client = new DeviceClient(connString, protocol, (ClientOptions) null);

        // act
        client.setOption("SetSASTokenExpiryTime", "thisIsNotALong");
    }

    //Tests_SRS_DEVICECLIENT_25_021: ["SetSASTokenExpiryTime" - time in seconds after which SAS Token expires.]
    @Test
    public void setOptionSASTokenExpiryTimeHTTPSucceeds()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = false;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.SAS_TOKEN;
            }
        };
        DeviceClient client = new DeviceClient(connString, protocol, (ClientOptions) null);
        final long value = 60;

        // act
        client.setOption("SetSASTokenExpiryTime", value);

        // assert
        new Verifications()
        {
            {
                mockConfig.getSasTokenAuthentication().setTokenValidSecs(value);
                times = 1;
            }
        };
    }

    //Tests_SRS_DEVICECLIENT_25_021: ["SetSASTokenExpiryTime" - time in seconds after which SAS Token expires.]
    //Tests_SRS_DEVICECLIENT_25_024: ["SetSASTokenExpiryTime" shall restart the transport if transport is already open after updating expiry time.]
    @Test
    public void setOptionSASTokenExpiryTimeAfterClientOpenHTTPSucceeds()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = true;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
                mockConfig.getSasTokenAuthentication().canRefreshToken();
                result = true;
                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.SAS_TOKEN;
            }
        };
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;

        DeviceClient client = new DeviceClient(connString, protocol, (ClientOptions) null);
        client.open();
        final long value = 60;

        // act
        client.setOption("SetSASTokenExpiryTime", value);

        // assert
        new Verifications()
        {
            {
                mockDeviceIO.close();
                times = 1;
                mockConfig.getSasTokenAuthentication().setTokenValidSecs(value);
                times = 1;
                Deencapsulation.invoke(mockDeviceIO, "open");
                times = 2;
            }
        };
    }

    /*Tests_SRS_DEVICECLIENT_25_024: ["SetSASTokenExpiryTime" shall restart the transport
                                    1. If the device currently uses device key and
                                    2. If transport is already open
                                    after updating expiry time.]
    */
    @Test
    public void setOptionSASTokenExpiryTimeAfterClientOpenTransportWithSasTokenSucceeds()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = true;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.SAS_TOKEN;
                mockIotHubSasTokenAuthenticationProvider.canRefreshToken();
                result = true;
            }
        };
        final String connString = "some string";
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;

        DeviceClient client = new DeviceClient(connString, protocol, (ClientOptions) null);
        client.open();
        final long value = 60;

        // act
        client.setOption("SetSASTokenExpiryTime", value);

        // assert
        new Verifications()
        {
            {
                mockDeviceIO.close();
                times = 1;
                mockConfig.getSasTokenAuthentication().setTokenValidSecs(value);
                times = 1;
                Deencapsulation.invoke(mockDeviceIO, "open");
                times = 2;
            }
        };
    }
    //Tests_SRS_DEVICECLIENT_25_021: ["SetSASTokenExpiryTime" - Time in secs to specify SAS Token Expiry time.]
    @Test
    public void setOptionSASTokenExpiryTimeAMQPSucceeds()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = false;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.SAS_TOKEN;
            }
        };

        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;

        DeviceClient client = new DeviceClient(connString, protocol, (ClientOptions) null);
        final long value = 60;

        // act
        client.setOption("SetSASTokenExpiryTime", value);

        // assert
        new Verifications()
        {
            {
                mockConfig.getSasTokenAuthentication().setTokenValidSecs(value);
                times = 1;
            }
        };
    }

    //Tests_SRS_DEVICECLIENT_25_021: ["SetSASTokenExpiryTime" - time in seconds after which SAS Token expires.]
    //Tests_SRS_DEVICECLIENT_25_024: ["SetSASTokenExpiryTime" shall restart the transport if transport is already open after updating expiry time.]
    @Test
    public void setOptionSASTokenExpiryTimeAfterClientOpenAMQPSucceeds()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = true;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
                mockConfig.getSasTokenAuthentication().canRefreshToken();
                result = true;
                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.SAS_TOKEN;
            }
        };
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;

        DeviceClient client = new DeviceClient(connString, protocol, (ClientOptions) null);
        client.open();
        final long value = 60;

        // act
        client.setOption("SetSASTokenExpiryTime", value);

        // assert
        new Verifications()
        {
            {
                mockDeviceIO.close();
                times = 1;
                mockConfig.getSasTokenAuthentication().setTokenValidSecs(value);
                times = 1;
                Deencapsulation.invoke(mockDeviceIO, "open");
                times = 2;
            }
        };
    }

    //Tests_SRS_DEVICECLIENT_25_021: [**"SetSASTokenExpiryTime" - Time in secs to specify SAS Token Expiry time.]
    @Test
    public void setOptionSASTokenExpiryTimeMQTTSucceeds()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        new NonStrictExpectations() {
            {
                mockDeviceIO.isOpen();
                result = false;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
                mockConfig.getSasTokenAuthentication().canRefreshToken();
                result = true;
                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.SAS_TOKEN;
            }
        };
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.MQTT;

        DeviceClient client = new DeviceClient(connString, protocol, (ClientOptions) null);
        final long value = 60;

        // act
        client.setOption("SetSASTokenExpiryTime", value);

        // assert
        new Verifications()
        {
            {
                mockConfig.getSasTokenAuthentication().setTokenValidSecs(value);
                times = 1;
            }
        };
    }

    //Tests_SRS_DEVICECLIENT_25_021: ["SetSASTokenExpiryTime" - time in seconds after which SAS Token expires.]
    //Tests_SRS_DEVICECLIENT_25_024: ["SetSASTokenExpiryTime" shall restart the transport if transport is already open after updating expiry time.]
    @Test
    public void setOptionSASTokenExpiryTimeAfterClientOpenMQTTSucceeds()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = true;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
                mockConfig.getSasTokenAuthentication().canRefreshToken();
                result = true;
                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.SAS_TOKEN;
            }
        };
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.MQTT;

        DeviceClient client = new DeviceClient(connString, protocol, (ClientOptions) null);
        client.open();
        final long value = 60;

        // act
        client.setOption("SetSASTokenExpiryTime", value);

        // assert
        new Verifications()
        {
            {
                mockDeviceIO.close();
                times = 1;
                mockConfig.getSasTokenAuthentication().setTokenValidSecs(value);
                times = 1;
                Deencapsulation.invoke(mockDeviceIO, "open");
                times = 2;
            }
        };
    }

    // Tests_SRS_DEVICECLIENT_12_027: [The function shall throw IOError if either the deviceIO or the tranportClient's open() or closeNow() throws.]
    @Test (expected = IOError.class)
    public void setOptionClientSASTokenExpiryTimeAfterClientOpenAMQPThrowsDeviceIOClose()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = true;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
                mockConfig.getSasTokenAuthentication().canRefreshToken();
                result = true;
                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.SAS_TOKEN;
                mockDeviceIO.close();
                result =  new IOException();
            }
        };
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;

        DeviceClient client = new DeviceClient(connString, protocol);
        Deencapsulation.setField(client, "config", mockConfig);
        Deencapsulation.setField(client, "deviceIO", mockDeviceIO);
        final long value = 60;

        // act
        client.setOption("SetSASTokenExpiryTime", value);
    }

    // Tests_SRS_DEVICECLIENT_12_027: [The function shall throw IOError if either the deviceIO or the tranportClient's open() or closeNow() throws.]
    @Test (expected = IOError.class)
    public void setOptionClientSASTokenExpiryTimeAfterClientOpenAMQPThrowsTransportDeviceIOOpen()
            throws DeviceClientException, URISyntaxException
    {
        // arrange
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = true;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
                mockConfig.getSasTokenAuthentication().canRefreshToken();
                result = true;
                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.SAS_TOKEN;
                Deencapsulation.invoke(mockDeviceIO, "open");
                result =  new IOException();
            }
        };
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;

        DeviceClient client = new DeviceClient(connString, protocol);
        Deencapsulation.setField(client, "config", mockConfig);
        Deencapsulation.setField(client, "deviceIO", mockDeviceIO);
        final long value = 60;

        // act
        client.setOption("SetSASTokenExpiryTime", value);
    }

    // Tests_SRS_DEVICECLIENT_34_075: [If the provided connection string contains a module id field, this function shall throw an UnsupportedOperationException.]
    @Test (expected = UnsupportedOperationException.class)
    public void ConstructorThrowsIfConnStringContainsModuleIdField() throws URISyntaxException
    {
        // arrange
        final String connString = "HostName=iothub.device.com;CredentialType=SharedAccessKey;deviceId=testdevice;"
                + "SharedAccessKey=adjkl234j52=";
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;
        new NonStrictExpectations()
        {
            {
                mockDeviceIO.isOpen();
                result = true;
                mockDeviceIO.getProtocol();
                result = IotHubClientProtocol.HTTPS;
                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.X509_CERTIFICATE;
                mockConfig.getModuleId();
                result = "any module id";
            }
        };

        //act
        new DeviceClient(connString, protocol);
    }

    /* Tests_SRS_INTERNALCLIENT_21_048: [If there is no instance of the FileUploadClient, the uploadToBlobAsync shall create a new instance of the FileUploadClient.] */
    @Test
    public void startFileUploadOneFileUploadInstanceSucceeds(@Mocked final FileUploadClient mockedFileUpload,
                                                             @Mocked final InputStream mockInputStream,
                                                             @Mocked final IotHubEventCallback mockedStatusCB,
                                                             @Mocked final PropertyCallBack mockedPropertyCB) throws DeviceClientException, URISyntaxException, TransportException
    {
        //arrange
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        final String destinationBlobName = "valid/blob/name.txt";
        final long streamLength = 100;

        //assert
        new Expectations()
        {
            {
                Deencapsulation.newInstance(FileUploadClient.class, mockConfig);
                result = mockedFileUpload;
                Deencapsulation.invoke(mockedFileUpload, "uploadToBlobAsync",
                        destinationBlobName, mockInputStream, streamLength, mockedStatusCB, mockedPropertyCB);
                times = 2;
            }
        };
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class, new Class[] {String.class, IotHubClientProtocol.class}, "some conn string", protocol);
        Deencapsulation.setField(client, "config", mockConfig);
        Deencapsulation.invoke(client, "uploadToBlobAsync", destinationBlobName, mockInputStream, streamLength, mockedStatusCB, mockedPropertyCB);

        // act
        Deencapsulation.invoke(client, "uploadToBlobAsync", destinationBlobName, mockInputStream, streamLength, mockedStatusCB, mockedPropertyCB);
    }

    /* Tests_SRS_INTERNALCLIENT_21_045: [If the `callback` is null, the uploadToBlobAsync shall throw IllegalArgumentException.] */
    @Test (expected = IllegalArgumentException.class)
    public void startFileUploadNullCallbackThrows(@Mocked final InputStream mockInputStream,
                                                  @Mocked final PropertyCallBack mockedPropertyCB) throws DeviceClientException, URISyntaxException, TransportException
    {
        //arrange
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        final String destinationBlobName = "valid/blob/name.txt";
        final long streamLength = 100;

        Deencapsulation.newInstance(DeviceClientConfig.class, new Class[] {String.class, IotHubClientProtocol.class}, "some conn string", protocol);
        deviceClientInstanceExpectation(protocol);
        InternalClient client = Deencapsulation.newInstance(InternalClient.class, new Class[] {IotHubConnectionString.class, IotHubClientProtocol.class, long.class, long.class, ClientOptions.class}, mockIotHubConnectionString, protocol, SEND_PERIOD, RECEIVE_PERIOD, null);

        // act
        Deencapsulation.invoke(client, "uploadToBlobAsync", destinationBlobName, mockInputStream, streamLength, null, mockedPropertyCB);
    }

    /* Tests_SRS_INTERNALCLIENT_21_046: [If the `inputStream` is null, the uploadToBlobAsync shall throw IllegalArgumentException.] */
    @Test (expected = IllegalArgumentException.class)
    public void startFileUploadNullInputStreamThrows(@Mocked final IotHubEventCallback mockedStatusCB,
                                                     @Mocked final PropertyCallBack mockedPropertyCB) throws DeviceClientException, URISyntaxException, TransportException
    {
        //arrange
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        final String destinationBlobName = "valid/blob/name.txt";
        final long streamLength = 100;

        DeviceClientConfig clientConfig = Deencapsulation.newInstance(DeviceClientConfig.class, new Class[] {String.class, IotHubClientProtocol.class}, "some conn string", protocol);
        deviceClientInstanceExpectation(protocol);
        InternalClient client = Deencapsulation.newInstance(InternalClient.class, new Class[] {IotHubConnectionString.class, IotHubClientProtocol.class, long.class, long.class, ClientOptions.class}, mockIotHubConnectionString, protocol, SEND_PERIOD, RECEIVE_PERIOD, null);

        // act
        Deencapsulation.invoke(client, "uploadToBlobAsync", destinationBlobName, (InputStream) null, streamLength, mockedStatusCB, mockedPropertyCB);
    }

    /* Tests_SRS_INTERNALCLIENT_21_052: [If the `streamLength` is negative, the uploadToBlobAsync shall throw IllegalArgumentException.] */
    @Test (expected = IllegalArgumentException.class)
    public void startFileUploadNegativeLengthThrows(@Mocked final IotHubEventCallback mockedStatusCB,
                                                    @Mocked final InputStream mockInputStream,
                                                    @Mocked final PropertyCallBack mockedPropertyCB) throws DeviceClientException, URISyntaxException, TransportException
    {
        //arrange
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        final String destinationBlobName = "valid/blob/name.txt";

        DeviceClientConfig clientConfig = Deencapsulation.newInstance(DeviceClientConfig.class, new Class[] {String.class, IotHubClientProtocol.class}, "some conn string", protocol);
        deviceClientInstanceExpectation(protocol);
        InternalClient client = Deencapsulation.newInstance(InternalClient.class, new Class[] {IotHubConnectionString.class, IotHubClientProtocol.class, long.class, long.class, ClientOptions.class}, mockIotHubConnectionString, protocol, SEND_PERIOD, RECEIVE_PERIOD, null);

        // act
        Deencapsulation.invoke(client, "uploadToBlobAsync", destinationBlobName, mockInputStream, -1, mockedStatusCB, mockedPropertyCB);
    }

    /* Tests_SRS_INTERNALCLIENT_21_047: [If the `destinationBlobName` is null, empty, or not valid, the uploadToBlobAsync shall throw IllegalArgumentException.] */
    @Test (expected = IllegalArgumentException.class)
    public void startFileUploadNullBlobNameThrows(@Mocked final InputStream mockInputStream,
                                                  @Mocked final IotHubEventCallback mockedStatusCB,
                                                  @Mocked final PropertyCallBack mockedPropertyCB) throws DeviceClientException, URISyntaxException, TransportException
    {
        //arrange
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        final long streamLength = 100;

        DeviceClientConfig clientConfig = Deencapsulation.newInstance(DeviceClientConfig.class, new Class[] {String.class, IotHubClientProtocol.class}, "some conn string", protocol);
        deviceClientInstanceExpectation(protocol);
        InternalClient client = Deencapsulation.newInstance(InternalClient.class, new Class[] {IotHubConnectionString.class, IotHubClientProtocol.class, long.class, long.class, ClientOptions.class}, mockIotHubConnectionString, protocol, SEND_PERIOD, RECEIVE_PERIOD, null);

        // act
        Deencapsulation.invoke(client, "uploadToBlobAsync", new Class[] {String.class, InputStream.class, long.class, IotHubEventCallback.class, Object.class}, null, mockInputStream, streamLength, mockedStatusCB, mockedPropertyCB);
    }

    /* Tests_SRS_INTERNALCLIENT_21_047: [If the `destinationBlobName` is null, empty, or not valid, the uploadToBlobAsync shall throw IllegalArgumentException.] */
    @Test (expected = IllegalArgumentException.class)
    public void startFileUploadEmptyBlobNameThrows(@Mocked final InputStream mockInputStream,
                                                   @Mocked final IotHubEventCallback mockedStatusCB,
                                                   @Mocked final PropertyCallBack mockedPropertyCB)
    {
        //arrange
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        final long streamLength = 100;

        DeviceClientConfig clientConfig = Deencapsulation.newInstance(DeviceClientConfig.class, new Class[] {String.class, IotHubClientProtocol.class}, "some conn string", protocol);
        deviceClientInstanceExpectation(protocol);
        InternalClient client = Deencapsulation.newInstance(InternalClient.class, new Class[] {IotHubConnectionString.class, IotHubClientProtocol.class, long.class, long.class, ClientOptions.class}, mockIotHubConnectionString, protocol, SEND_PERIOD, RECEIVE_PERIOD, null);

        // act
        Deencapsulation.invoke(client, "uploadToBlobAsync", "", mockInputStream, streamLength, mockedStatusCB, mockedPropertyCB);
    }

    /* Tests_SRS_INTERNALCLIENT_21_047: [If the `destinationBlobName` is null, empty, or not valid, the uploadToBlobAsync shall throw IllegalArgumentException.] */
    @Test (expected = IllegalArgumentException.class)
    public void startFileUploadInvalidUTF8BlobNameThrows(@Mocked final InputStream mockInputStream,
                                                         @Mocked final IotHubEventCallback mockedStatusCB,
                                                         @Mocked final PropertyCallBack mockedPropertyCB) throws DeviceClientException, URISyntaxException, TransportException
    {
        //arrange
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        final String destinationBlobName = "valid\u1234/blob/name.txt";
        final long streamLength = 100;

        DeviceClientConfig clientConfig = Deencapsulation.newInstance(DeviceClientConfig.class, new Class[] {String.class, IotHubClientProtocol.class}, "some conn string", protocol);
        deviceClientInstanceExpectation(protocol);
        InternalClient client = Deencapsulation.newInstance(InternalClient.class, new Class[] {IotHubConnectionString.class, IotHubClientProtocol.class, long.class, long.class, ClientOptions.class}, mockIotHubConnectionString, protocol, SEND_PERIOD, RECEIVE_PERIOD, null);

        // act
        Deencapsulation.invoke(client, "uploadToBlobAsync", destinationBlobName, mockInputStream, streamLength, mockedStatusCB, mockedPropertyCB);
    }

    /* Tests_SRS_INTERNALCLIENT_21_044: [The uploadToBlobAsync shall asynchronously upload the stream in `inputStream` to the blob in `destinationBlobName`.] */
    /* Tests_SRS_INTERNALCLIENT_21_048: [If there is no instance of the FileUploadClient, the uploadToBlobAsync shall create a new instance of the FileUploadClient.] */
    /* Tests_SRS_INTERNALCLIENT_21_050: [The uploadToBlobAsync shall start the stream upload process, by calling uploadToBlobAsync on the FileUploadClient class.] */
    @Test
    public void startFileUploadSucceeds(@Mocked final FileUploadClient mockedFileUpload,
                                        @Mocked final InputStream mockInputStream,
                                        @Mocked final IotHubEventCallback mockedStatusCB,
                                        @Mocked final PropertyCallBack mockedPropertyCB) throws DeviceClientException, URISyntaxException, TransportException
    {
        //arrange
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        final String destinationBlobName = "valid/blob/name.txt";
        final long streamLength = 100;

        // assert
        new Expectations()
        {
            {
                Deencapsulation.newInstance(FileUploadClient.class, new Class[] {DeviceClientConfig.class}, (DeviceClientConfig) any);
                result = mockedFileUpload;
                Deencapsulation.invoke(mockedFileUpload, "uploadToBlobAsync",
                        destinationBlobName, mockInputStream, streamLength, mockedStatusCB, mockedPropertyCB);
            }
        };
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class, new Class[] {String.class, IotHubClientProtocol.class}, "some conn string", protocol);

        // act
        Deencapsulation.invoke(client, "uploadToBlobAsync", destinationBlobName, mockInputStream, streamLength, mockedStatusCB, mockedPropertyCB);
    }

    /* Tests_SRS_INTERNALCLIENT_21_054: [If the fileUpload is not null, the closeNow shall call closeNow on fileUpload.] */
    @Test
    public void closeNowClosesFileUploadSucceeds(@Mocked final FileUploadClient mockedFileUpload,
                                                 @Mocked final InputStream mockInputStream,
                                                 @Mocked final IotHubEventCallback mockedStatusCB,
                                                 @Mocked final PropertyCallBack mockedPropertyCB) throws DeviceClientException, URISyntaxException, TransportException
    {
        //arrange
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        final String destinationBlobName = "valid/blob/name.txt";
        final long streamLength = 100;

        new NonStrictExpectations()
        {
            {
                Deencapsulation.newInstance(FileUploadClient.class, new Class[] {DeviceClientConfig.class}, (DeviceClientConfig) any);
                result = mockedFileUpload;
                Deencapsulation.invoke(mockedFileUpload, "uploadToBlobAsync",
                        destinationBlobName, mockInputStream, streamLength, mockedStatusCB, mockedPropertyCB);
            }
        };
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class, new Class[] {String.class, IotHubClientProtocol.class, ClientOptions.class}, "some conn string", protocol, null);
        Deencapsulation.invoke(client, "open");
        Deencapsulation.invoke(client, "uploadToBlobAsync", destinationBlobName, mockInputStream, streamLength, mockedStatusCB, mockedPropertyCB);

        // act
        client.closeNow();

        // assert
        new Verifications()
        {
            {
                Deencapsulation.invoke(mockedFileUpload, "closeNow");
                times = 1;
            }
        };
    }

    /* Tests_SRS_INTERNALCLIENT_21_049: [If uploadToBlobAsync failed to create a new instance of the FileUploadClient, it shall bypass the exception.] */
    @Test (expected = IllegalArgumentException.class)
    public void startFileUploadNewInstanceThrows(@Mocked final FileUploadClient mockedFileUpload,
                                                 @Mocked final InputStream mockInputStream,
                                                 @Mocked final IotHubEventCallback mockedStatusCB,
                                                 @Mocked final PropertyCallBack mockedPropertyCB) throws DeviceClientException, URISyntaxException, TransportException
    {
        //arrange
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        final String destinationBlobName = "valid/blob/name.txt";
        final long streamLength = 100;

        new NonStrictExpectations()
        {
            {
                Deencapsulation.newInstance(FileUploadClient.class, new Class[] {DeviceClientConfig.class}, (DeviceClientConfig) any);
                result = new IllegalArgumentException();
            }
        };
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class, new Class[] {String.class, IotHubClientProtocol.class}, "some conn string", protocol);

        // act
        Deencapsulation.invoke(client, "uploadToBlobAsync", destinationBlobName, mockInputStream, streamLength, mockedStatusCB, mockedPropertyCB);
    }

    /* Tests_SRS_INTERNALCLIENT_21_051: [If uploadToBlobAsync failed to start the upload using the FileUploadClient, it shall bypass the exception.] */
    @Test (expected = IllegalArgumentException.class)
    public void startFileUploadUploadToBlobAsyncThrows(@Mocked final FileUploadClient mockedFileUpload,
                                                       @Mocked final InputStream mockInputStream,
                                                       @Mocked final IotHubEventCallback mockedStatusCB,
                                                       @Mocked final PropertyCallBack mockedPropertyCB) throws DeviceClientException, URISyntaxException, TransportException
    {
        //arrange
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        final String destinationBlobName = "valid/blob/name.txt";
        final long streamLength = 100;

        new NonStrictExpectations()
        {
            {
                Deencapsulation.newInstance(FileUploadClient.class, new Class[] {DeviceClientConfig.class}, (DeviceClientConfig) any);
                result = mockedFileUpload;
                Deencapsulation.invoke(mockedFileUpload, "uploadToBlobAsync",
                        destinationBlobName, mockInputStream, streamLength, mockedStatusCB, mockedPropertyCB);
                result = new IllegalArgumentException();
            }
        };
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class, new Class[] {String.class, IotHubClientProtocol.class}, "some conn string", protocol);

        // act
        Deencapsulation.invoke(client, "uploadToBlobAsync", destinationBlobName, mockInputStream, streamLength, mockedStatusCB, mockedPropertyCB);
    }

    // Tests_SRS_DEVICECLIENT_12_028: [The constructor shall shall set the config, deviceIO and tranportClient to null.]
    @Test
    public void unusedConstructor()
    {
        // act
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);

        // assert
        assertNull(Deencapsulation.getField(client, "config"));
        assertNull(Deencapsulation.getField(client, "deviceIO"));
    }

    @Test
    public void setAmqpOpenAuthenticationSessionTimeout() throws DeviceClientException
    {
        //arrange
        final int timeoutInSeconds = 10;
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);
        Deencapsulation.setField(client, "config", mockConfig);
        Deencapsulation.setField(client, "deviceIO", mockDeviceIO);

        new NonStrictExpectations()
        {
            {
                mockConfig.getProtocol();
                result = IotHubClientProtocol.AMQPS;

                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.SAS_TOKEN;
            }
        };

        //act
        client.setOption("SetAmqpOpenAuthenticationSessionTimeout", timeoutInSeconds);

        //assert
        new Verifications() {
            {
                Deencapsulation.invoke(mockConfig, "setAmqpOpenAuthenticationSessionTimeout", timeoutInSeconds);
                times = 1;
            }
        };
    }

    @Test
    public void setAmqpWsOpenAuthenticationSessionTimeout() throws DeviceClientException
    {
        //arrange
        final int timeoutInSeconds = 10;
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);
        Deencapsulation.setField(client, "config", mockConfig);
        Deencapsulation.setField(client, "deviceIO", mockDeviceIO);

        new NonStrictExpectations()
        {
            {
                mockConfig.getProtocol();
                result = IotHubClientProtocol.AMQPS_WS;

                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.SAS_TOKEN;
            }
        };

        //act
        client.setOption("SetAmqpOpenAuthenticationSessionTimeout", timeoutInSeconds);

        //assert
        new Verifications() {
            {
                Deencapsulation.invoke(mockConfig, "setAmqpOpenAuthenticationSessionTimeout", timeoutInSeconds);
                times = 1;
            }
        };
    }

    @Test
    public void setNullAmqpWsOpenAuthenticationSessionTimeoutThrows() throws DeviceClientException
    {
        //arrange
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);
        Deencapsulation.setField(client, "config", mockConfig);

        try {
            //act
            client.setOption("setAmqpOpenAuthenticationSessionTimeout", null);
        } catch (IllegalArgumentException expected) {
            //assert
            assertEquals("value is null", expected.getMessage());
        }
    }

    @Test
    public void setIncorrectAmqpOpenAuthenticationSessionTimeoutThrows() throws DeviceClientException
    {
        //arrange
        String timeoutInSeconds = "ten";
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);
        Deencapsulation.setField(client, "config", mockConfig);
        Deencapsulation.setField(client, "deviceIO", mockDeviceIO);

        new NonStrictExpectations()
        {
            {
                mockConfig.getProtocol();
                result = IotHubClientProtocol.AMQPS;

                mockConfig.getAuthenticationType();
                result = DeviceClientConfig.AuthType.SAS_TOKEN;
            }
        };

        try {
            //act
            client.setOption("SetAmqpOpenAuthenticationSessionTimeout", timeoutInSeconds);
        } catch (IllegalArgumentException expected) {
            //assert
            assertEquals("value is not int = " + timeoutInSeconds, expected.getMessage());
        }
    }

    @Test
    public void setAmqpOpenAuthenticationSessionTimeoutForHttpThrows() throws DeviceClientException
    {
        //arrange
        int timeoutInSeconds = 10;
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);
        Deencapsulation.setField(client, "config", mockConfig);
        Deencapsulation.setField(client, "deviceIO", mockDeviceIO);

        new NonStrictExpectations()
        {
            {
                mockConfig.getProtocol();
                result = protocol;
            }
        };

        try {
            //act
            client.setOption("SetAmqpOpenAuthenticationSessionTimeout", timeoutInSeconds);
        } catch (UnsupportedOperationException expected) {
            //assert
            assertEquals("Cannot set the open authentication session timeout when using protocol " + protocol, expected.getMessage());
        }
    }

    @Test
    public void setAmqpOpenAuthenticationSessionTimeoutForMqttThrows() throws DeviceClientException
    {
        //arrange
        int timeoutInSeconds = 10;
        final IotHubClientProtocol protocol = IotHubClientProtocol.MQTT;
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);
        Deencapsulation.setField(client, "config", mockConfig);
        Deencapsulation.setField(client, "deviceIO", mockDeviceIO);

        new NonStrictExpectations()
        {
            {
                mockConfig.getProtocol();
                result = protocol;
            }
        };

        try {
            //act
            client.setOption("SetAmqpOpenAuthenticationSessionTimeout", timeoutInSeconds);
        } catch (UnsupportedOperationException expected) {
            //assert
            assertEquals("Cannot set the open authentication session timeout when using protocol " + protocol, expected.getMessage());
        }
    }

    @Test
    public void setAmqpOpenAuthenticationSessionTimeoutForMqttWsThrows() throws DeviceClientException
    {
        //arrange
        int timeoutInSeconds = 10;
        final IotHubClientProtocol protocol = IotHubClientProtocol.MQTT_WS;
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);
        Deencapsulation.setField(client, "config", mockConfig);
        Deencapsulation.setField(client, "deviceIO", mockDeviceIO);

        new NonStrictExpectations()
        {
            {
                mockConfig.getProtocol();
                result = protocol;
            }
        };

        try {
            //act
            client.setOption("SetAmqpOpenAuthenticationSessionTimeout", timeoutInSeconds);
        } catch (UnsupportedOperationException expected) {
            //assert
            assertEquals("Cannot set the open authentication session timeout when using protocol " + protocol, expected.getMessage());
        }
    }

    @Test
    public void setAmqpOpenAuthenticationSessionTimeoutForX509Throws() throws DeviceClientException
    {
        //arrange
        int timeoutInSeconds = 10;
        final IotHubClientProtocol protocol = IotHubClientProtocol.AMQPS;
        final DeviceClientConfig.AuthType authType = DeviceClientConfig.AuthType.X509_CERTIFICATE;
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);
        Deencapsulation.setField(client, "config", mockConfig);
        Deencapsulation.setField(client, "deviceIO", mockDeviceIO);

        new NonStrictExpectations()
        {
            {
                mockConfig.getProtocol();
                result = protocol;

                mockConfig.getAuthenticationType();
                result = authType;
            }
        };

        try {
            //act
            client.setOption("SetAmqpOpenAuthenticationSessionTimeout", timeoutInSeconds);
        } catch (UnsupportedOperationException expected) {
            //assert
            assertEquals("Cannot set the open authentication session timeout when using authentication type " + authType, expected.getMessage());
        }
    }

    @Test
    public void setOpenDeviceSessionsTimeout() throws DeviceClientException
    {
        //arrange
        final int timeoutInSeconds = 10;
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);
        Deencapsulation.setField(client, "config", mockConfig);
        Deencapsulation.setField(client, "deviceIO", mockDeviceIO);

        new NonStrictExpectations()
        {
            {
                mockConfig.getProtocol();
                result = IotHubClientProtocol.AMQPS;
            }
        };

        //act
        client.setOption("SetAmqpOpenDeviceSessionsTimeout", timeoutInSeconds);

        //assert
        new Verifications() {
            {
                Deencapsulation.invoke(mockConfig, "setAmqpOpenDeviceSessionsTimeout", timeoutInSeconds);
                times = 1;
            }
        };
    }

    @Test
    public void setNullOpenDeviceSessionsTimeoutThrows() throws DeviceClientException
    {
        //arrange
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);
        Deencapsulation.setField(client, "config", mockConfig);

        try {
            //act
            client.setOption("SetAmqpOpenDeviceSessionsTimeout", null);
        } catch (IllegalArgumentException expected) {
            //assert
            assertEquals("value is null", expected.getMessage());
        }
    }

    @Test
    public void setIncorrectOpenDeviceSessionsTimeoutThrows() throws DeviceClientException
    {
        //arrange
        String timeoutInSeconds = "ten";
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);
        Deencapsulation.setField(client, "config", mockConfig);
        Deencapsulation.setField(client, "deviceIO", mockDeviceIO);

        new NonStrictExpectations()
        {
            {
                mockConfig.getProtocol();
                result = IotHubClientProtocol.AMQPS;
            }
        };

        try {
            //act
            client.setOption("SetAmqpOpenDeviceSessionsTimeout", timeoutInSeconds);
        } catch (IllegalArgumentException expected) {
            //assert
            assertEquals("value is not int = " + timeoutInSeconds, expected.getMessage());
        }
    }

    public void setOpenDeviceSessionsTimeoutForHttpThrows() throws DeviceClientException
    {
        //arrange
        String timeoutInSeconds = "ten";
        final IotHubClientProtocol protocol = IotHubClientProtocol.HTTPS;
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);
        Deencapsulation.setField(client, "config", mockConfig);

        new NonStrictExpectations()
        {
            {
                mockConfig.getProtocol();
                result = protocol;
            }
        };

        try {
            //act
            client.setOption("SetAmqpOpenDeviceSessionsTimeout", timeoutInSeconds);
        } catch (IllegalArgumentException expected) {
            //assert
            assertEquals("Cannot set the open device session timeout when using protocol " + protocol, expected.getMessage());
        }
    }

    public void setOpenDeviceSessionsTimeoutForMqttThrows() throws DeviceClientException
    {
        //arrange
        String timeoutInSeconds = "ten";
        final IotHubClientProtocol protocol = IotHubClientProtocol.MQTT;
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);
        Deencapsulation.setField(client, "config", mockConfig);

        new NonStrictExpectations()
        {
            {
                mockConfig.getProtocol();
                result = protocol;
            }
        };

        try {
            //act
            client.setOption("SetAmqpOpenDeviceSessionsTimeout", timeoutInSeconds);
        } catch (IllegalArgumentException expected) {
            //assert
            assertEquals("Cannot set the open device session timeout when using protocol " + protocol, expected.getMessage());
        }
    }

    public void setOpenDeviceSessionsTimeoutForMqttWsThrows() throws DeviceClientException
    {
        //arrange
        String timeoutInSeconds = "ten";
        final IotHubClientProtocol protocol = IotHubClientProtocol.MQTT_WS;
        DeviceClient client = Deencapsulation.newInstance(DeviceClient.class);
        Deencapsulation.setField(client, "config", mockConfig);

        new NonStrictExpectations()
        {
            {
                mockConfig.getProtocol();
                result = protocol;
            }
        };

        try {
            //act
            client.setOption("SetAmqpOpenDeviceSessionsTimeout", timeoutInSeconds);
        } catch (IllegalArgumentException expected) {
            //assert
            assertEquals("Cannot set the open device session timeout when using protocol " + protocol, expected.getMessage());
        }
    }

    private void deviceClientInstanceExpectation(final IotHubClientProtocol protocol)
    {
        final long receivePeriod;
        if (protocol == IotHubClientProtocol.HTTPS)
        {
            receivePeriod = RECEIVE_PERIOD_MILLIS_HTTPS;
        }
        else
        {
            receivePeriod = RECEIVE_PERIOD_MILLIS_AMQPS;
        }

        new Expectations()
        {
            {
                Deencapsulation.newInstance(DeviceClientConfig.class, mockIotHubConnectionString);
                result = mockConfig;
                Deencapsulation.newInstance(DeviceIO.class,
                        mockConfig, SEND_PERIOD_MILLIS, receivePeriod);
                result = mockDeviceIO;
            }
        };
    }
}
