/*
 *  Copyright (c) Microsoft. All rights reserved.
 *  Licensed under the MIT license. See LICENSE file in the project root for full license information.
 */

package com.microsoft.azure.sdk.iot.deps.auth;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Objects;
import java.util.UUID;

public class IotHubSSLContext
{
    private SSLContext sslContext;

    private static final String TRUSTED_IOT_HUB_CERT_PREFIX = "trustedIotHubCert-";

    public IotHubSSLContext()
    {
        try
        {
            // Only loads public certs. Private keys are in password protected keystores,
            // so they can't be retrieved in this constructor. Because no private keys are loaded,
            // this SSLContext can only be used in connections that are authenticated via symmetric keys.
            this.sslContext = SSLContext.getDefault();

            // Initializing the SSLContext with null keyManagers and null trustManagers makes it so the device's default
            // trusted certificates are loaded, and no private keys are loaded.
            this.sslContext.init(null, null, new SecureRandom());
        }
        catch (NoSuchAlgorithmException | KeyManagementException e)
        {
            throw new IllegalStateException("Failed to build the default SSLContext instance", e);
        }
    }

    public IotHubSSLContext(SSLContext sslContext)
    {
        Objects.requireNonNull(sslContext);
        this.sslContext = sslContext;
    }

    public static SSLContext getSSLContextFromString(String trustedCertificates) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException
    {
        Objects.requireNonNull(trustedCertificates);
        Collection<? extends Certificate> certificates;
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        try (InputStream inputStream = new ByteArrayInputStream(trustedCertificates.getBytes()))
        {
            certificates = certificateFactory.generateCertificates(inputStream);
        }

        TrustManagerFactory trustManagerFactory = generateTrustManagerFactory(certificates);

        SSLContext sslContext = SSLContext.getDefault();
        sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
        return sslContext;
    }

    public static SSLContext getSSLContextFromFile(String trustedCertificatesFilePath) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException
    {
        Objects.requireNonNull(trustedCertificatesFilePath);

        Collection<? extends Certificate> certificates;
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        try (FileInputStream fis = new FileInputStream(trustedCertificatesFilePath))
        {
            certificates = certificateFactory.generateCertificates(fis);
        }

        TrustManagerFactory trustManagerFactory = generateTrustManagerFactory(certificates);

        SSLContext sslContext = SSLContext.getDefault();
        sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
        return sslContext;
    }

    public SSLContext getSSLContext()
    {
        return this.sslContext;
    }

    private static TrustManagerFactory generateTrustManagerFactory( Collection<? extends Certificate> certificates)
        throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException
    {
        KeyStore trustKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustKeyStore.load(null);

        for (Certificate c : certificates)
        {
            trustKeyStore.setCertificateEntry(TRUSTED_IOT_HUB_CERT_PREFIX + UUID.randomUUID(), c);
        }

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustKeyStore);

        return trustManagerFactory;
    }
}
