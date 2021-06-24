/*
 *
 *  Copyright (c) Microsoft. All rights reserved.
 *  Licensed under the MIT license. See LICENSE file in the project root for full license information.
 *
 */

package com.microsoft.azure.sdk.iot.provisioning.security;

import com.microsoft.azure.sdk.iot.provisioning.security.exceptions.SecurityProviderException;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.UUID;

public abstract class SecurityProviderX509 extends SecurityProvider
{
    private static final String ALIAS_CERT_ALIAS = "ALIAS_CERT";

    abstract public String getClientCertificateCommonName();
    abstract public X509Certificate getClientCertificate();
    abstract public Key getClientPrivateKey();
    abstract public Collection<X509Certificate> getIntermediateCertificatesChain();

    @Override
    public String getRegistrationId() throws SecurityProviderException
    {
        //SRS_SecurityClientX509_25_001: [ This method shall retrieve the commonName of the client certificate and return as registration Id. ]
        return this.getClientCertificateCommonName();
    }

    @Override
    public SSLContext getSSLContext() throws SecurityProviderException
    {
        try
        {
            return this.generateSSLContext(this.getClientCertificate(), this.getClientPrivateKey(), this.getIntermediateCertificatesChain());
        }
        catch (NoSuchProviderException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException | IOException | CertificateException e)
        {
            throw new SecurityProviderException(e);
        }
    }

    private TrustManager[] getDefaultX509TrustManager(KeyStore keyStore) throws NoSuchAlgorithmException, KeyStoreException
    {
        // obtain X509 trust manager
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        return trustManagerFactory.getTrustManagers();
    }

    private KeyManager[] getDefaultX509KeyManager(KeyStore keyStore, String password) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, SecurityProviderException
    {
        // create key manager factory and obtain x509 key manager
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, password.toCharArray());
        return keyManagerFactory.getKeyManagers();
    }

    private SSLContext generateSSLContext(X509Certificate leafCertificate, Key leafPrivateKey, Collection<X509Certificate> signerCertificates) throws NoSuchProviderException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException, CertificateException, SecurityProviderException
    {
        if (leafCertificate == null || leafPrivateKey == null || signerCertificates == null)
        {
            throw new IllegalArgumentException("cert or private key cannot be null");
        }

        String password = UUID.randomUUID().toString();
        SSLContext sslContext = SSLContext.getInstance(DEFAULT_TLS_PROTOCOL);
        // Load Trusted certs to keystore and retrieve it.

        KeyStore keyStore = this.getKeyStoreWithTrustedCerts();

        if (keyStore == null)
        {
            throw new SecurityProviderException("Key store with trusted certs cannot be null");
        }

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
        keyStore.setKeyEntry(ALIAS_CERT_ALIAS, leafPrivateKey, password.toCharArray(), certs);

        sslContext.init(this.getDefaultX509KeyManager(keyStore, password), this.getDefaultX509TrustManager(keyStore), new SecureRandom());
        return sslContext;
    }
}
