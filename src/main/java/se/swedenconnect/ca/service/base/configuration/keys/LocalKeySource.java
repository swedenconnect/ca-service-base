/*
 * Copyright (c) 2021. Agency for Digital Government (DIGG)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.swedenconnect.ca.service.base.configuration.keys;


import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;
import se.swedenconnect.opensaml.pkcs11.credential.PKCS11Credential;
import se.swedenconnect.opensaml.pkcs11.credential.PKCS11NoTestCredential;
import se.swedenconnect.opensaml.pkcs11.providerimpl.PKCS11NullProvider;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

@Slf4j
public class LocalKeySource {

    private X509Credential credential;
    private String keySourceType, keySourceLocation, keySourcePassword, keySourceAlias, keySourceCertLocation;
    private String entityId, countryCode, orgName;
    private boolean nullAlias;
    private PKCS11Provider pkcs11Provider;
    private boolean pkcs11ReloadableKeys;

    public LocalKeySource(
            String keySourceType,
            String keySourceLocation,
            String keySourcePassword,
            String keySourceAlias,
            String keySourceCertLocation,
            PKCS11Provider pkcs11Provider,
            Boolean pkcs11ReloadableKeys) {
        this.keySourceType = keySourceType;
        this.keySourceCertLocation = keySourceCertLocation;
        this.nullAlias = keySourceAlias == null;
        this.keySourceAlias = nullAlias ? "default-alias" : keySourceAlias;
        this.keySourcePassword = keySourcePassword == null ? "Password01" : keySourcePassword;
        this.keySourceLocation = keySourceLocation;
        this.entityId = null;
        this.countryCode = "XX";
        this.orgName = "Test Org";
        this.pkcs11Provider = pkcs11Provider;
        this.pkcs11ReloadableKeys = pkcs11ReloadableKeys != null && pkcs11ReloadableKeys;

        try {
            credential = loadKeyStore();
        } catch (Exception e) {
            log.error("Failed to generate service keyStore", e);
        }
    }

    /**
     * Get the credential
     * @return credential
     */
    public X509Credential getCredential() {
        return credential;
    }

    /**
     * Get the certificate of the local key source credential
     * @return local key source certificate
     */
    public X509Certificate getCertificate() {
        return credential.getEntityCertificate();
    }

    private X509Credential getCredentialFromKeyStore(KeyStore keyStore) throws KeyStoreException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException {
        Certificate cert = getCertFromKeyStore(keyStore);
        X509Certificate certificate = BasicX509Utils.getCertificate(cert.getEncoded());
        PrivateKey key = (PrivateKey) keyStore.getKey(this.keySourceAlias, this.keySourcePassword.toCharArray());
        BasicX509Credential bcred = new BasicX509Credential(certificate, key);
        bcred.setEntityId(entityId);
        return bcred;
    }

    private Certificate getCertFromKeyStore(KeyStore keyStore) throws KeyStoreException, IllegalArgumentException {
        if (nullAlias) {
            // If the keySourceAlias was not set as input. Try to find a private key entry and use it.
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    keySourceAlias = alias;
                    return keyStore.getCertificate(alias);
                }
            }
        } else {
            // If alias was provided. It must match. Select that key.
            if (keyStore.isKeyEntry(keySourceAlias)) {
                return keyStore.getCertificate(keySourceAlias);
            }
            throw new IllegalArgumentException("Selected key store has no private key under specified alias");
        }
        throw new IllegalArgumentException("Selected key store has no private key");
    }

    private X509Credential loadKeyStore() throws Exception {
        if (keySourceType == null) {
            return null;
        }
        switch (keySourceType.toLowerCase()) {
            case "jks":
                log.info("Loading JKS key store");
                return getJksKeyCredential(false);
            case "pkcs12":
                log.info("Loading PKCS12 key");
                return getJksKeyCredential(true);
            case "pem":
                log.info("Loading key from pem key and certificate");
                return getPemKeyCredential();
            case "pkcs11":
                log.info("Loading key from PKCS11 token");
                return getPkcs11Credential();
            case "create":
                log.info("Creating new in-memory key store");
                return createCredential();
            default:
                log.error("Invalid keySourceType '{}'. Expecting one of 'jks', 'pkcs12', 'pem' or 'create'.", keySourceType);
                throw new IllegalArgumentException("Illegal Key Source Type declaration in application.properties");
        }

    }

    private X509Credential getPkcs11Credential() throws Exception {
        if (pkcs11Provider instanceof PKCS11NullProvider) {
            //No valid configuration for PKCS11 tokes are provided.
            throw new IllegalArgumentException("Illegal Key Source Type declaration in application.properties - Missing PKCS11 configuration for PKCS11 token");
        }

        // Look for an externally configured certificate
        X509CertificateHolder extCert = null;
        try {
            List<Object> certPemObjects = BasicX509Utils.getPemObjects(getSourceInputStream(keySourceCertLocation));
            extCert = certPemObjects.stream()
              .filter(o -> o instanceof X509CertificateHolder)
              .map(o -> (X509CertificateHolder) o)
              .findFirst()
              .orElse(null);
        } catch (Exception ex) {
            log.debug("Unable to locate certificate using external file resource");
        }

        //Attempt to recover the certificate from the HSM
        X509CertificateHolder hsmCert = null;
        try {
            List<String> providerNameList = pkcs11Provider.getProviderNameList();
            for (String providerName: providerNameList){
                KeyStore keyStore = KeyStore.getInstance("PKCS11", providerName);
                keyStore.load(null, this.keySourcePassword.toCharArray());
                hsmCert = new X509CertificateHolder(keyStore.getCertificate(this.keySourceAlias).getEncoded());
            }
        } catch (Exception ex) {
            log.debug("No certificate was obtained from the hsm slot");
        }

        if (extCert == null && hsmCert == null) {
            throw new IllegalArgumentException("Illegal Key Source Type declaration in application.properties - Missing external certificate declaration");
        }

        X509Certificate certificate = BasicX509Utils.getCertificate(
          extCert != null
            ? extCert.getEncoded()
            : hsmCert.getEncoded()
        );
        BasicX509Credential bcred;
        if (pkcs11ReloadableKeys){
            bcred = new PKCS11Credential(certificate, pkcs11Provider.getProviderNameList(), keySourceAlias, keySourcePassword);
        } else {
            bcred = new PKCS11NoTestCredential(certificate, pkcs11Provider.getProviderNameList(), keySourceAlias, keySourcePassword);
        }
        bcred.setEntityId(entityId);
        return bcred;
    }

    private X509Credential getPemKeyCredential() throws IOException, PKCSException, OperatorCreationException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        List<Object> keyPemObjects = BasicX509Utils.getPemObjects(getSourceInputStream(keySourceLocation), keySourcePassword);
        Optional<PrivateKey> privateKeyOptional = keyPemObjects.stream()
                .filter(o -> o instanceof KeyPair || o instanceof PrivateKey)
                .map(o -> {
                    if (o instanceof KeyPair) {
                        return ((KeyPair) o).getPrivate();
                    }
                    return (PrivateKey) o;
                }).findFirst();

        List<Object> certPemObjects = BasicX509Utils.getPemObjects(getSourceInputStream(keySourceCertLocation));
        Optional<X509CertificateHolder> certificateHolderOptional = certPemObjects.stream()
                .filter(o -> o instanceof X509CertificateHolder)
                .map(o -> (X509CertificateHolder) o)
                .findFirst();

        if (privateKeyOptional.isPresent() && certificateHolderOptional.isPresent()) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);
            X509Certificate certificate = BasicX509Utils.getCertificate(certificateHolderOptional.get().getEncoded());
            keyStore.setKeyEntry(keySourceAlias, privateKeyOptional.get(), keySourcePassword.toCharArray(), new Certificate[]{certificate});

            PrivateKey key = (PrivateKey) keyStore.getKey(this.keySourceAlias, this.keySourcePassword.toCharArray());
            BasicX509Credential bcred = new BasicX509Credential(certificate, key);
            bcred.setEntityId(entityId);
            return bcred;
        }

        throw new IllegalArgumentException("Unable to create key store from provided PEM parameters");
    }

    private X509Credential getJksKeyCredential(boolean pkcs12) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keyStore;
        InputStream ksInstream;
        ksInstream = getSourceInputStream(keySourceLocation);
        keyStore = pkcs12 ? KeyStore.getInstance("PKCS12") : KeyStore.getInstance("JKS");
        keyStore.load(ksInstream, keySourcePassword.toCharArray());
        return getCredentialFromKeyStore(keyStore);
    }

    private InputStream getSourceInputStream(String location) throws FileNotFoundException {
        if (location.startsWith("classpath:")) {
            return getClass().getResourceAsStream("/" + location.substring(10));
        }
        return new FileInputStream(location);
    }


    private X509Credential createCredential() throws IllegalArgumentException {

        KeyStore keyStore;
        try {
            //Generate Subject DN
            Map<X509DnNameType, String> nameMap = new HashMap<>();
            nameMap.put(X509DnNameType.CN, "Autogenerated SVT Issuer key");
            nameMap.put(X509DnNameType.Country, countryCode);
            nameMap.put(X509DnNameType.Org, orgName);
            X500Name subjectDN = BasicX509Utils.getDn(nameMap);
            log.debug("Generated new key source certificate");
            log.debug("subjectDN = " + subjectDN.toString());

            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);
            log.debug("Generating keys");
            KeyPair kp = generateKeyPair("RSA", 2048);
            log.debug("Generating cert");
            X509Certificate certificate = BasicX509Utils.generateV1Certificate(kp, subjectDN);
            log.debug("Setting key store entry");
            log.debug("Alias:{} Password:{}", keySourceAlias, keySourcePassword);
            log.debug("KeyPresent:{}", kp == null ? "false" : "true");
            log.trace("Cert:{}", certificate == null ? "NULL Cert" : certificate.toString());
            keyStore.setKeyEntry(keySourceAlias, kp.getPrivate(), keySourcePassword.toCharArray(), new Certificate[]{certificate});
            log.debug("Generated new key store");

            PrivateKey key = (PrivateKey) keyStore.getKey(this.keySourceAlias, this.keySourcePassword.toCharArray());
            BasicX509Credential bcred = new BasicX509Credential(certificate, key);
            bcred.setEntityId(entityId);
            return bcred;
        } catch (Exception ex) {
            log.debug("KeyStore generation error", ex);
            throw new IllegalArgumentException("New key store generation failed");
        }
    }

    private KeyPair generateKeyPair(String algorithm, int bits) throws NoSuchAlgorithmException {
        KeyPair kp;
        KeyPairGenerator generator;
        generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(bits);
        kp = generator.generateKeyPair();
        return kp;
    }


}
