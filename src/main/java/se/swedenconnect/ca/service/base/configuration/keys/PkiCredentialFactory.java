/*
 * Copyright 2024 Sweden Connect
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
import se.swedenconnect.security.credential.container.ManagedPkiCredential;
import se.swedenconnect.security.credential.pkcs11.FilePkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.Pkcs11Configuration;
import se.swedenconnect.security.credential.pkcs11.Pkcs11Credential;
import se.swedenconnect.security.credential.pkcs11.SunPkcs11CertificatesAccessor;
import se.swedenconnect.security.credential.pkcs11.SunPkcs11PrivateKeyAccessor;

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
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Implements a factory for creating credentials based on configuration data.
 */
@Slf4j
public class PkiCredentialFactory {

  /** Country code for self issued certificates used in mock key generation. */
  @Setter
  private String mockKeyCountryCode;

  /** Organization name for self issued certificates used in mock key generation */
  @Setter
  private String mockKeyOrgName;

  /** Key length used in generated mock RSA keys */
  @Setter
  private int mockKeyLen = 2048;

  /** PKCS11 crypto provider for a present HSM slot, if available. */
  private final Provider pkcs11Provider;
  private final String pkcs11ConfigurationLocation;

  /**
   * Constructor for the PKI credential factory
   *
   * @param pkcs11ConfigFilePath file path to optional PKCS#11 configuration data
   */
  public PkiCredentialFactory(final String pkcs11ConfigFilePath) {
    this.mockKeyCountryCode = "XX";
    this.mockKeyOrgName = "Test Org";
    this.pkcs11ConfigurationLocation = pkcs11ConfigFilePath;

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
  public ManagedPkiCredential getCredential(final CAConfigData.KeySourceType keySourceType,
      final File keySourceLocation,
      final String alias, final char[] password, final File certificateFile) throws Exception {

    KeyStore keyStore = null;
    switch (keySourceType) {
    case jks:
      keyStore = KeyStore.getInstance("JKS");
      keyStore.load(new FileSystemResource(keySourceLocation).getInputStream(), password);
      new KeyStoreCredential(keyStore, alias, password);
      return new ManagedPkiCredential(new KeyStoreCredential(keyStore, alias, password),
          c -> this.destroyNopCallback(), null);
    case pkcs12:
      keyStore = KeyStore.getInstance("PKCS12");
      keyStore.load(new FileSystemResource(keySourceLocation).getInputStream(), password);
      return new ManagedPkiCredential(new KeyStoreCredential(keyStore, alias, password),
          c -> this.destroyNopCallback(), null);
    case pkcs11:
      if (this.pkcs11Provider == null) {
        throw new IllegalArgumentException("PKCS11 provider must be set for PKCS 11 key sources");
      }
      Pkcs11Configuration pkcs11Configuration = new FilePkcs11Configuration(pkcs11ConfigurationLocation);
      Pkcs11Credential p11Credential =
          new Pkcs11Credential(pkcs11Configuration, alias, password, new SunPkcs11PrivateKeyAccessor(),
              new SunPkcs11CertificatesAccessor());
      log.trace("Initially loaded key credential certificate:\n{}", p11Credential.getCertificate());
      if (certificateFile != null) {
        X509Certificate preconfiguredP11Certificate = CertUtil.readCertificate(certificateFile);
        log.debug(
            "PKCS#11 key setup with externally configured certificate. Replacing credential certificate with configured certificate");
        log.trace("Replacing with preconfigured certificate:\n{}", preconfiguredP11Certificate);
        p11Credential = new Pkcs11Credential(pkcs11Configuration, alias, password, new SunPkcs11PrivateKeyAccessor(),
            List.of(preconfiguredP11Certificate));
      }
      else {
        log.debug("No externally configured PKCS11 certificate. Using certificate from HSM");
      }
      return new ManagedPkiCredential(p11Credential, c -> this.destroyNopCallback(), null);
    case pem:
      Objects.requireNonNull(keySourceLocation, "Key source location must not be null for pem key sources");
      Objects.requireNonNull(certificateFile, "Certificate file location must not be null for pem key sources");
      final PEMKey pemKey = new PEMKey(new FileSystemResource(keySourceLocation),
          Arrays.toString(password));
      final BasicCredential pemCredential = new BasicCredential(CertUtil.readCertificate(certificateFile),
          pemKey.privateKey);
      return new ManagedPkiCredential(pemCredential, c -> this.destroyNopCallback(), null);
    case none:
      return null;
    case create:
      return this.createCredential();
    }
    throw new IOException("Unable to create credential");
  }

  private ManagedPkiCredential createCredential() throws IllegalArgumentException {

    final String keySourceAlias = "alias";
    final char[] keySourcePassword = "S3cr3tPass".toCharArray();

    KeyStore keyStore;
    try {
      // Generate Subject DN
      final Map<X509DnNameType, String> nameMap = new HashMap<>();
      nameMap.put(X509DnNameType.CN, "Autogenerated SVT Issuer key");
      nameMap.put(X509DnNameType.Country, this.mockKeyCountryCode);
      nameMap.put(X509DnNameType.Org, this.mockKeyOrgName);
      final X500Name subjectDN = BasicX509Utils.getDn(nameMap);
      log.debug("Generated new key source certificate");
      log.debug("subjectDN = " + subjectDN);

      keyStore = KeyStore.getInstance("JKS");
      keyStore.load(null, null);
      log.debug("Generating keys");
      final KeyPair kp = this.generateKeyPair();
      log.debug("Generating cert");
      final X509Certificate certificate = BasicX509Utils.generateV1Certificate(kp, subjectDN);
      log.debug("Setting key store entry");
      log.trace("Cert:{}", certificate == null ? "NULL Cert" : certificate.toString());
      keyStore.setKeyEntry(keySourceAlias, kp.getPrivate(), keySourcePassword, new Certificate[] { certificate });
      log.debug("Generated new key store");

      final PrivateKey key = (PrivateKey) keyStore.getKey(keySourceAlias, keySourcePassword);
      assert certificate != null;
      return new ManagedPkiCredential(new BasicCredential(certificate, key), c -> this.destroyNopCallback(), null);
    }
    catch (final Exception ex) {
      log.debug("KeyStore generation error", ex);
      throw new IllegalArgumentException("New key store generation failed");
    }
  }

  private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
    KeyPair kp;
    KeyPairGenerator generator;
    generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(this.mockKeyLen);
    kp = generator.generateKeyPair();
    return kp;
  }

  private void destroyNopCallback() {
  }
}
