/*
 * Copyright 2021-2022 Sweden Connect
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

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.cryptacular.util.CertUtil;
import org.springframework.core.io.FileSystemResource;
import se.swedenconnect.ca.service.base.configuration.properties.CAConfigData;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Implements a factory for creating credentials based on configuration data.
 */
@Slf4j
public class PkiCredentialFactory {

    /** Country code for self issued certificates used in mock key generation. */
    @Setter private String mockKeyCountryCode;
    /** Organization name for self issued certificates used in mock key generation */
    @Setter private String mockKeyOrgName;
    /** Key length used in generated mock RSA keys */
    @Setter private int mockKeyLen = 2048;

    /** PKCS11 crypto provider for a present HSM slot, if available. */
    private final Provider pkcs11Provider;

    /**
     * Constructor for the PKI credential factory
     *
     * @param pkcs11ConfigFilePath file path to optional PKCS#11 configuration data
     */
    public PkiCredentialFactory(String pkcs11ConfigFilePath) {
        this.mockKeyCountryCode = "XX";
        this.mockKeyOrgName = "Test Org";

        Provider createdPkcs11Provider = null;
        if (pkcs11ConfigFilePath != null) {
            createdPkcs11Provider = Security.getProvider("SunPKCS11");
            createdPkcs11Provider = createdPkcs11Provider.configure(pkcs11ConfigFilePath);
            Security.addProvider(createdPkcs11Provider);
        }
        this.pkcs11Provider = createdPkcs11Provider;
    }

    /**
     * Get the credential associated with provided credential configuration data.
     *
     * @param keySourceType the type of key source (jks, pkcs12, pkcs11, pem, create or none)
     * @param keySourceLocation the location of the key pair data
     * @param alias alias used to access the credential key pair
     * @param password password protecting the private key source
     * @param certificateFile external certificate file if present
     * @return {@link PkiCredential}
     * @throws Exception errors obtaining PKI credential from configuration data
     */
    public PkiCredential getCredential(final CAConfigData.KeySourceType keySourceType, final File keySourceLocation, final String alias,
      final char[] password, File certificateFile) throws Exception {

        switch (keySourceType) {
        case jks:
        case pkcs12:
            Objects.requireNonNull(keySourceLocation, "Key source location must not be null for key store key sources");
            KeyStoreCredential keyStoreCredential = new KeyStoreCredential(
              new FileSystemResource(keySourceLocation),
              keySourceType.name().toUpperCase(),
              password, alias, password
            );
            keyStoreCredential.init();
            return keyStoreCredential;
        case pkcs11:
            Objects.requireNonNull(pkcs11Provider, "PKCS11 provider must be set for PKCS 11 key sources");
            KeyStoreCredential p11Credential = new KeyStoreCredential(
              null, "PKCS11", pkcs11Provider.getName(),
              password, alias, null
            );
            p11Credential.init();
            return p11Credential;
        case pem:
            Objects.requireNonNull(keySourceLocation, "Key source location must not be null for pem key sources");
            Objects.requireNonNull(certificateFile, "Certificate file location must not be null for pem key sources");
            PEMKey pemKey = new PEMKey(new FileSystemResource(keySourceLocation),
              Arrays.toString(password));
            BasicCredential pemCredential = new BasicCredential(CertUtil.readCertificate(certificateFile),
              pemKey.privateKey
            );
            pemCredential.init();
            return pemCredential;
        case none:
            return null;
        case create:
            return createCredential();
        }
        throw new IOException("Unable to create credential");
    }


    private PkiCredential createCredential() throws IllegalArgumentException {

        String keySourceAlias = "alias";
        char[] keySourcePassword = "S3cr3tPass".toCharArray();

        KeyStore keyStore;
        try {
            //Generate Subject DN
            Map<X509DnNameType, String> nameMap = new HashMap<>();
            nameMap.put(X509DnNameType.CN, "Autogenerated SVT Issuer key");
            nameMap.put(X509DnNameType.Country, mockKeyCountryCode);
            nameMap.put(X509DnNameType.Org, mockKeyOrgName);
            X500Name subjectDN = BasicX509Utils.getDn(nameMap);
            log.debug("Generated new key source certificate");
            log.debug("subjectDN = " + subjectDN);

            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);
            log.debug("Generating keys");
            KeyPair kp = generateKeyPair();
            log.debug("Generating cert");
            X509Certificate certificate = BasicX509Utils.generateV1Certificate(kp, subjectDN);
            log.debug("Setting key store entry");
            log.trace("Cert:{}", certificate == null ? "NULL Cert" : certificate.toString());
            keyStore.setKeyEntry(keySourceAlias, kp.getPrivate(), keySourcePassword, new Certificate[]{certificate});
            log.debug("Generated new key store");

            PrivateKey key = (PrivateKey) keyStore.getKey(keySourceAlias, keySourcePassword);
            return new BasicCredential(certificate, key);
        } catch (Exception ex) {
            log.debug("KeyStore generation error", ex);
            throw new IllegalArgumentException("New key store generation failed");
        }
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPair kp;
        KeyPairGenerator generator;
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(mockKeyLen);
        kp = generator.generateKeyPair();
        return kp;
    }
}
