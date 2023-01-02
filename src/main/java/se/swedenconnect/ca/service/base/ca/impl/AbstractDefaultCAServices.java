/*
 * Copyright 2023 Sweden Connect
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
package se.swedenconnect.ca.service.base.ca.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.context.ApplicationEventPublisher;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.issuer.impl.BasicCertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.impl.SelfIssuedCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.AttributeTypeAndValueModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.ExtendedKeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.impl.ExplicitCertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.SelfIssuedCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPModel;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.ca.engine.revocation.ocsp.impl.RepositoryBasedOCSPResponder;
import se.swedenconnect.ca.engine.utils.CAUtils;
import se.swedenconnect.ca.service.base.configuration.BasicServiceConfig;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventEnum;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventFactory;
import se.swedenconnect.ca.service.base.configuration.audit.CAAuditEventData;
import se.swedenconnect.ca.service.base.configuration.instance.InstanceConfiguration;
import se.swedenconnect.ca.service.base.configuration.keys.BasicX509Utils;
import se.swedenconnect.ca.service.base.configuration.keys.PkiCredentialFactory;
import se.swedenconnect.ca.service.base.configuration.properties.CAConfigData;
import se.swedenconnect.ca.service.base.configuration.properties.EntityNameProperties;
import se.swedenconnect.ca.service.base.utils.GeneralCAUtils;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * This implementation of CA Services assumes a set file structure within an instances folder Where each instance has
 * its onw folder with the name of the instance key. each instance folder have the following sub folders:
 * <ul>
 * <li>keys</li>
 * <li>certs</li>
 * <li>repository</li>
 * </ul>
 *
 * <p>
 * The "keys" folder contains the key or key store files used by this instance
 * </p>
 * <p>
 * The "certs" can hold 2 files "ca-cert-chain.pem" and "self-issued.crt"
 * </p>
 * <p>
 * The "repository folder holds any files related to the implementation of the CA repository
 * </p>
 */
@Slf4j
public abstract class AbstractDefaultCAServices extends AbstractCAServices {

  private final File instancesDir;
  private final Map<String, CAConfigData> instanceConfigMap;
  private final Map<String, CAService> caServicesMap;
  private final PkiCredentialFactory pkiCredentialFactory;
  private final BasicServiceConfig basicServiceConfig;
  private final Map<String, CARepository> caRepositoryMap;
  private final ApplicationEventPublisher applicationEventPublisher;

  /**
   * Abstract default CA service constructor.
   *
   * @param instanceConfiguration CA service instance configuration
   * @param pkiCredentialFactory factory for creating PkiCredential from configuration data
   * @param basicServiceConfig basic service configuration data
   * @param caRepositoryMap ca repository map
   * @param applicationEventPublisher application event publisher for audit logging
   */
  public AbstractDefaultCAServices(final InstanceConfiguration instanceConfiguration,
      final PkiCredentialFactory pkiCredentialFactory, final BasicServiceConfig basicServiceConfig,
      final Map<String, CARepository> caRepositoryMap, final ApplicationEventPublisher applicationEventPublisher) {
    super(instanceConfiguration);
    this.applicationEventPublisher = applicationEventPublisher;
    this.pkiCredentialFactory = pkiCredentialFactory;
    this.basicServiceConfig = basicServiceConfig;
    this.instancesDir = new File(basicServiceConfig.getDataStoreLocation(), "instances");
    this.instanceConfigMap = instanceConfiguration.getInstanceConfigMap();
    this.caRepositoryMap = caRepositoryMap;
    this.caServicesMap = new HashMap<>();
    this.instanceConfigMap.keySet().forEach(instance -> {
      this.caServicesMap.put(instance, this.getCaService(instance));
    });
  }

  /**
   * Main function to create or reassemble a CA instance based on configuration properties
   *
   * <p>
   * Process to create a CA service instance is:
   * </p>
   * <ul>
   * <li>Create key credentials which includes locating key and cert. If key is generated. Then clear all history
   * data</li>
   * <li>Locate and test CA certificate. If not found. Then issue a self issued CA certificate</li>
   * <li>If OCSP is enabled then locate OCSP service certificate. If not found, then issue an OCSP certificate. finally
   * create the OCSP service</li>
   * <li>Assemble CAService</li>
   * </ul>
   *
   * @param instance
   * @return
   */
  private CAService getCaService(final String instance) {
    log.debug("Creating the CA instance {}", instance);

    try {
      // Extract config data
      final CAConfigData caConfigData = this.instanceConfigMap.get(instance);
      final CAConfigData.CaConfig caConfig = caConfigData.getCa();
      final CAConfigData.KeySourceData caKeyConf = caConfig.getKeySource();
      final CAConfigData.OCSPConfig ocspConfig = caConfigData.getOcsp();

      // Get key storage folders for this instance
      final File instanceDir = new File(this.instancesDir, instance);
      final File keyDir = this.createOrLoadDir(instanceDir, "keys");
      final File certsDir = this.createOrLoadDir(instanceDir, "certs");
      final File repositoryDir = this.createOrLoadDir(instanceDir, "repository");

      log.debug("Creating the local key store for the CA of instance {}", instance);
      final PkiCredential caKeySource = this.getKeySource(caKeyConf, keyDir, "ca",
          keyDir, certsDir, repositoryDir);
      assert caKeySource != null;

      // Locate any existing CA Certs
      final String chainFileName = this.locateFile(certsDir, "chain.pem", null);
      List<X509CertificateHolder> caChain = this.getCertChainFromPemFile(chainFileName);
      log.debug("Found {} preconfigured certificates in the CA certificate chain", caChain.size());
      X509CertificateHolder caCert;

      if (caChain.isEmpty()) {
        // There is no chain stored on file. Generate and save new self issued CA cert
        log.debug("Generating new self signed certificate for instance {}", instance);
        caCert =
            this.generateSelfIssuedCaCert(caKeySource, caConfigData, instance, this.basicServiceConfig.getServiceUrl());

        // Create self-issued CA certificate issuance audit log event
        this.applicationEventPublisher
            .publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.selfSignedCACertIsssued,
                new CAAuditEventData(
                    instance,
                    Base64.toBase64String(caCert.getEncoded()),
                    caCert.getSerialNumber(),
                    caCert.getSubject().toString()),
                null, AuditEventFactory.DEFAULT_AUDIT_PRINCIPAL));

        log.debug("Self signed CA cert issued for {}", caCert.getSubject().toString());
        caChain = Collections.singletonList(caCert);
        // Set the created CA chain as the credential chain
        final File chainFile = new File(certsDir, "ca-chain.pem");
        final File selfIssuedCaCertFile = new File(certsDir, "ca-self-signed.crt");
        FileUtils.writeStringToFile(chainFile, BasicX509Utils.getPemCert(caCert.getEncoded()), StandardCharsets.UTF_8);
        FileUtils.writeStringToFile(selfIssuedCaCertFile, BasicX509Utils.getPemCert(caCert.getEncoded()), StandardCharsets.UTF_8);
        log.debug("Saved new self issued CA certificate to {}", chainFile.getAbsolutePath());
      }
      else {
        // We found a certificate chain for this CA. use that and select the first cert as CA certificate
        caCert = caChain.get(0);
        log.debug("Found pre-configured CA certificate for {}", caCert.getSubject().toString());
      }

      // Validate the CA certificate
      log.debug("Validating the CA certificate match against the CA signing key for instance {}", instance);
      this.validateCertAndKey(caKeySource, caCert);

      // As we validated that the first certificate is the CA certificate. Make sure that the rest of the chain is in
      // order:
      caChain = BasicX509Utils.getOrderedCertList(caChain, caCert);
      // Finally, assign the certificate chain to the key source
      caKeySource.setCertificateChain(CAUtils.getCertList(caChain));
      if (log.isDebugEnabled()) {
        log.debug("Final ordered chain for ca instance {} is {}", instance,
            String.join(", ", caChain.stream()
                .map(x509CertificateHolder -> x509CertificateHolder.getSubject().toString())
                .collect(Collectors.toList())));
      }

      // Create CRL service and CA repository
      final CARepository caRepository = this.caRepositoryMap.get(instance);
      log.debug("Setting up CA Repository for instance {}", instance);
      final String crlDistrPoint = this.basicServiceConfig.getServiceUrl() + "/crl/" + instance + ".crl";
      log.debug("Setting CRL distribution point for instance {} to {}", instance, crlDistrPoint);
      final CRLIssuerModel crlIssuerModel = this.getCRLIssuerModel(caConfig, caCert, crlDistrPoint, caRepository,
        caConfig.getCrlMaxDurationBeforeUpgrade());

      // Create CA service with repository and CRL service
      log.debug("Instantiating the CA Service with CRL issuer for instance {}", instance);
      final CertificateIssuerModel certIssuerModel = this.getCertificateIssuerModel(caConfig);
      final AbstractBasicCA caService = this.getBasicCaService(instance, caConfig.getType(), caKeySource, caRepository,
          certIssuerModel, crlIssuerModel, Collections.singletonList(crlDistrPoint));

      // Get OCSP service
      log.debug("Setting up OCSP responder for instance {}", instance);
      final CAConfigData.KeySourceData ocspKeyConf = ocspConfig.getKeySource();
      final boolean ocspEnabled = ocspConfig.getEnabled();
      if (ocspEnabled) {
        // OCSP service is enabled for this CA. Get the configured key source
        log.debug("Setting up key source for OCSP responder {}", instance);
        // Set initial values for the OCSP certificate chain and algorithm
        List<X509CertificateHolder> ocspServiceChain = new ArrayList<>(caChain);
        String ocspAlgorithm = caConfig.getAlgorithm();
        PkiCredential ocspKeySource = this.getKeySource(ocspKeyConf, keyDir, "ocsp");
        // Determine if the OCSP responder is a separate entity based on whether we found a separate OCSP responder key
        final boolean separateOcspEntity = ocspKeySource != null;

        X509CertificateHolder ocspIssuerCert = null;
        if (separateOcspEntity) {
          log.debug("Setting up OCSP responder as separate entity with its own signing key");
          // OCSP provider is a separate entity. Get or generate the OCSP certificate and set algorithm to the OCSP
          // configured algorithm
          ocspAlgorithm = ocspConfig.getAlgorithm();
          final String ocspCertFileName = this.locateFile(certsDir, "ocsp.crt", null);

          if (ocspCertFileName == null) {
            log.debug("Found no preconfigured OCSP signer certificate. Issuing a new OCSP signer certificate");
            // No OCSP certificate file was found. Generate a new OCSP certificate and save it

            ocspIssuerCert =
                this.generateOcspCertificate(caKeySource, caCert, ocspKeySource.getCertificate().getPublicKey(),
                    caConfigData, instance);

            // Create OCSP certificate issuance audit log event
            this.applicationEventPublisher
                .publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.ocspCertificateIssued,
                    new CAAuditEventData(
                        instance,
                        Base64.toBase64String(ocspIssuerCert.getEncoded()),
                        ocspIssuerCert.getSerialNumber(),
                        ocspIssuerCert.getSubject().toString()),
                    null, AuditEventFactory.DEFAULT_AUDIT_PRINCIPAL));

            log.debug("Issued a new OCSP certificate for {}", ocspIssuerCert.getSubject().toString());
            // Save OCSP cert
            FileUtils.writeStringToFile(
                new File(certsDir, "ocsp.crt"),
                BasicX509Utils.getPemCert(ocspIssuerCert.getEncoded()));
            log.debug("Saved new OCSP signer certificate at {}", certsDir.getAbsolutePath() + "/ocsp.crt");
          }
          else {
            // There is an existing OCSP certificate. Use that.
            ocspIssuerCert = new JcaX509CertificateHolder(
                Objects.requireNonNull(
                    BasicX509Utils.getCertOrNull(
                        FileUtils.readFileToByteArray(
                            new File(ocspCertFileName)))));
            log.debug("Found pre-configured OCSP certificate for {}", ocspIssuerCert.getSubject().toString());
          }
          // Validate the ocsp issuer certificate and add it to the OCSP validation chain.
          ocspServiceChain.add(ocspIssuerCert);
          // Sort certificate chain order
          ocspServiceChain = BasicX509Utils.getOrderedCertList(ocspServiceChain, ocspIssuerCert);
          // Finally, assign the certificate chain to the OCSP key source
          ocspKeySource.setCertificateChain(CAUtils.getCertList(ocspServiceChain));
          log.debug("Setting up OCSP responder with issuer certificate containing {} certificates",
              ocspServiceChain.size());
          // Pick the first cert in the chain as the OCSP certificate
          ocspIssuerCert = ocspServiceChain.get(0);
          // Validate that this cert has the correct public key
          log.debug("Validating OCSP signing certificate match with OCSP signing key for instance {}", instance);
          this.validateCertAndKey(ocspKeySource, ocspIssuerCert);
        }
        else {
          log.debug(
              "OCSP responder does not have its own signing key. Signing OCSP responses with CA key for instance {}",
              instance);
          // OCSP has no separate key source. Use the CA key source instead
          ocspKeySource = caKeySource;
        }

        // Now we have everything to create the OCSP service instance
        log.debug("Instantiating OCSP responder for instance {}", instance);
        final OCSPModel ocspModel = this.getOCSPmodel(caService.getCaCertificate(), ocspAlgorithm, ocspConfig);
        final OCSPResponder ocspResponder = this.createOcspResponder(ocspKeySource, ocspModel, caRepository);
        // Add the OCSP responder to the CA service
        log.debug("Adding OCSP responder to instance {}", instance);
        caService.setOcspResponder(ocspResponder);
        // Set the OCSP responder URL
        caService.setOcspResponderUrl(this.basicServiceConfig.getServiceUrl() + "/ocsp/" + instance);
        caService.setOcspCertificate(ocspIssuerCert);
        log.debug("Setting OCSP service URL for instance {} to {}", instance, caService.getOCSPResponderURL());
      }
      else {
        log.debug("OCSP responder disabled for instance {}", instance);
      }

      log.info("Setup of CA Service instance {} completed", instance);

      return caService;
    }
    catch (final Exception ex) {
      // Catching any error here represents a fatal error in the CA configuration setup.
      log.error("Failure to create CA instance {}", instance, ex);
      throw new RuntimeException(ex);
    }

  }

  /**
   * Overridable method that creates the OCSPResponder for the CA
   *
   * @param ocspKeySource the credential for the OCSP responder
   * @param ocspModel model for creating OCSP responses
   * @param caRepository ca repository
   * @return {@link OCSPResponder}
   * @throws NoSuchAlgorithmException the specified algorithm is not supported
   */
  protected OCSPResponder createOcspResponder(final PkiCredential ocspKeySource, final OCSPModel ocspModel,
      final CARepository caRepository)
      throws NoSuchAlgorithmException {
    return new RepositoryBasedOCSPResponder(ocspKeySource, ocspModel, caRepository);
  }

  /**
   * Creates an instance of a Basic CA Service
   *
   * @param instance the instance of the CA being created
   * @param type the type of CA being created
   * @param issuerCredential private key and certificate chain credential of the issuing CA
   * @param caRepository CA Repository
   * @param certIssuerModel Certificate issuance model
   * @param crlIssuerModel CRL issuer model
   * @param crlDistributionPoints CRL Distribution point URL list
   * @return Basic CA Service instance
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   * @throws IOException input output data error
   * @throws CertificateEncodingException error encoding certificates
   */
  protected abstract AbstractBasicCA getBasicCaService(String instance, String type, PkiCredential issuerCredential,
      CARepository caRepository, CertificateIssuerModel certIssuerModel, CRLIssuerModel crlIssuerModel,
      List<String> crlDistributionPoints)
      throws NoSuchAlgorithmException, IOException, CertificateEncodingException;

  /**
   * Allows the implementation of this abstract class to modify the content of the OCSP certificate
   *
   * @param certModelBuilder the certificate modes builder used to create the certificate model
   * @param instance the instance of the CA the OCSP responder is associated with
   */
  protected abstract void customizeOcspCertificateModel(DefaultCertificateModelBuilder certModelBuilder,
      String instance);

  /**
   * Function used to create a certificate for the OCSP responder. The OCSP certificate is produced outside of the
   * regular audited certificate issuing process of certificates stored in the CA repository. This because the OCSP
   * responder certificate is not a certificate issued to a "customer" of the CA using the certificate policy that
   * governs the CA, but rather an internal service certificate for the service key used to sign OCSP responses, and for
   * which no revocation data is provided.
   *
   * <p>
   * For this reson the OCSP certificate is issued by the CA:s certificate issuer function directly without involvement
   * of the CA repository.
   * </p>
   *
   * @param caKeySource the issuer keys used by the CA to issue the OCSP certificate
   * @param issuerCert the issuing certificate of the CA
   * @param ocspPublicKey the public key of the OCSP responder
   * @param caConfigData configuration data of the CA service
   * @param instance the CA instance of the OCSP responder
   * @return OCSP responder certificate
   * @throws NoSuchAlgorithmException algorithm is not supported
   * @throws IOException error processing data
   */
  protected X509CertificateHolder generateOcspCertificate(final PkiCredential caKeySource,
      final X509CertificateHolder issuerCert,
      final PublicKey ocspPublicKey, final CAConfigData caConfigData, final String instance)
      throws NoSuchAlgorithmException, IOException {
    final CAConfigData.CaConfig caConfig = caConfigData.getCa();
    if (caConfig.getSelfIssuedValidYears() == null) {
      log.error("Illegal self issued validity configuration");
      throw new RuntimeException("Illegal self issued validity configuration - null");
    }
    final CAConfigData.OCSPConfig ocspConfig = caConfigData.getOcsp();

    final CAConfigData.ValidityData validity = caConfig.getValidity();
    int validityAmount = validity.getAmount();
    final Integer ocspCertValidityAmount = caConfig.getOcspCertValidityAmount();
    if (ocspCertValidityAmount != null && ocspCertValidityAmount > 0) {
      validityAmount = ocspCertValidityAmount;
    }
    final CertificateIssuerModel certificateIssuerModel = new CertificateIssuerModel(caConfig.getAlgorithm(),
        GeneralCAUtils
            .getDurationFromTypeAndValue(
                CAConfigData.ValidityUnit.Y, caConfig.getSelfIssuedValidYears()));
    certificateIssuerModel.setExpiryOffset(Duration.ofDays(validityAmount));
    certificateIssuerModel.setStartOffset(Duration.ofSeconds(validity.getStartOffsetSec()));

    final CertificateIssuer issuer = new BasicCertificateIssuer(certificateIssuerModel, caKeySource);
    final DefaultCertificateModelBuilder certModelBuilder = DefaultCertificateModelBuilder.getInstance(
        ocspPublicKey, issuerCert, certificateIssuerModel)
        .subject(this.getSubjectNameModel(ocspConfig.getName()))
        .basicConstraints(new BasicConstraintsModel(false, false))
        .includeAki(true)
        .includeSki(true)
        .keyUsage(new KeyUsageModel(KeyUsage.digitalSignature))
        .ocspNocheck(true)
        .extendedKeyUsage(new ExtendedKeyUsageModel(true, KeyPurposeId.id_kp_OCSPSigning));

    // Allow the implementation of this abstract class to modify the OCSP certificate content
    this.customizeOcspCertificateModel(certModelBuilder, instance);
    return issuer.issueCertificate(certModelBuilder.build());
  }

  /**
   * Generate self issued certificate. Note that this function does NOT engage the CA repository as the self issued
   * certificate is not a trusted certificate and not part of the certificates issued and maintained by this CA, and as
   * such can never be revoked.
   *
   * <p>
   * Implementations of this function are supposed to create a CertificateIssuerInstance with the key of the CA and
   * simply create a self signed certificate that can be used initially as the CA certificate of this CA service
   * </p>
   *
   * @param caKeySource CA key source
   * @param caConfigData CA configuration properties
   * @param instance The instance identifier
   * @param baseUrl base URL
   * @return self issued certificate
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   * @throws CertificateIssuanceException error issuing certificate
   */
  protected abstract X509CertificateHolder generateSelfIssuedCaCert(PkiCredential caKeySource,
      CAConfigData caConfigData, String instance,
      String baseUrl)
      throws NoSuchAlgorithmException, CertificateIssuanceException;

  /**
   * Default implementation of the self issued cert generation that may be used when implementing the
   * generateSelfIssuedCaCert abstract method
   *
   * @param caKeySource CA key source
   * @param caConfigData CA configuration properties
   * @return self issued certificate
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   * @throws CertificateIssuanceException error issuing certificate
   */
  protected X509CertificateHolder defaultGenerateSelfIssuedCaCert(final PkiCredential caKeySource,
      final CAConfigData caConfigData)
      throws NoSuchAlgorithmException, CertificateIssuanceException {
    final CAConfigData.CaConfig caConfig = caConfigData.getCa();
    if (caConfig.getSelfIssuedValidYears() == null) {
      log.error("Illegal self issued validity configuration");
      throw new RuntimeException("Illegal self issued validity configuration - null");
    }

    final CertificateIssuerModel certificateIssuerModel = new CertificateIssuerModel(
        caConfig.getAlgorithm(),
        GeneralCAUtils.getDurationFromTypeAndValue(CAConfigData.ValidityUnit.Y, caConfig.getSelfIssuedValidYears()));
    final CertificateIssuer issuer = new SelfIssuedCertificateIssuer(certificateIssuerModel);
    final CertificateModel certModel = SelfIssuedCertificateModelBuilder.getInstance(
        caKeySource.getPrivateKey(),
        caKeySource.getCertificate().getPublicKey(),
        certificateIssuerModel)
        .subject(this.getSubjectNameModel(caConfig.getName()))
        .basicConstraints(new BasicConstraintsModel(true, true))
        .keyUsage(new KeyUsageModel(KeyUsage.keyCertSign + KeyUsage.cRLSign, true))
        .includeSki(true)
        .certificatePolicy(new CertificatePolicyModel(true))
        .build();
    return issuer.issueCertificate(certModel);
  }

  /**
   * Validates the key source against the configured certificate for the key source key
   *
   * @param keySource key source
   * @param certificate certificate for the public key of the key source
   * @throws IOException on error in the input data
   */
  private void validateCertAndKey(final PkiCredential keySource, final X509CertificateHolder certificate)
      throws IOException {
    assert keySource != null;
    final boolean caCertKeyMatch = Arrays.equals(
        Objects.requireNonNull(keySource.getCertificate().getPublicKey()).getEncoded(),
        certificate.getSubjectPublicKeyInfo().getEncoded());
    if (!caCertKeyMatch) {
      throw new IOException("Configured CA certificate does not match configured CA key");
    }
  }

  /**
   * Gets a key source based on configuration data.
   *
   * <p>
   * The certificate used in the key source is a dummy certificate in the context of the CA. It is a certificate created
   * when generating the key that is necessary to match the current PKCS#11 implementation library. This certificate is
   * not used as CA or OCSP certificate as those certificates are created and stored separately
   * </p>
   *
   * @param keyConf key configuration data from properties settings of this key
   * @param keyDir the directory where key and key cert files are located
   * @param entityIdentifier a prefix that must occur before the file extension of relevant key resource files
   * @param cleanDirs a list of directories that should be wiped of all content if this key is created from scratch to
   *          delete history of any old key
   * @return key source
   */
  private PkiCredential getKeySource(final CAConfigData.KeySourceData keyConf, final File keyDir,
      final String entityIdentifier,
      final File... cleanDirs)
      throws Exception {
    String keyLocation = null;
    String certLocation = null;
    switch (keyConf.getType()) {
    case none:
      return null;
    case create:
      for (final File file : cleanDirs) {
        try {
          FileUtils.cleanDirectory(file);
        }
        catch (final IOException e) {
          log.error("Failed to delete configured directory {}", file.getAbsolutePath(), e);
        }
      }
      break;
    case jks:
      keyLocation = this.locateFile(keyDir, entityIdentifier + ".jks", keyConf.getResource());
      break;
    case pem:
      keyLocation = this.locateFile(keyDir, entityIdentifier + ".key", null);
    case pkcs11:
      certLocation = this.locateFile(keyDir, entityIdentifier + ".crt", null);
      break;
    case pkcs12:
      keyLocation = this.locateFile(keyDir, entityIdentifier + ".p12", keyConf.getResource());
      break;
    }

    return this.pkiCredentialFactory.getCredential(
        keyConf.getType(),
        keyLocation != null ? new File(keyLocation) : null,
        keyConf.getAlias(),
        keyConf.getPass() != null ? keyConf.getPass().toCharArray() : null,
        certLocation != null ? new File(certLocation) : null);
  }

  /**
   * Setup the OCSP model
   *
   * @param caCertificate CA certificate used to issue the certificates that are checked for revocation
   * @param ocspAlgorithm the algorithm URI representing the OCSP response signing algorithm
   * @param ocspConfig configuration data for the OCSP responder
   * @return OCSP model
   */
  private OCSPModel getOCSPmodel(final X509CertificateHolder caCertificate, final String ocspAlgorithm,
      final CAConfigData.OCSPConfig ocspConfig) {
    final OCSPModel ocspModel = new OCSPModel(caCertificate, ocspAlgorithm);

    final CAConfigData.ValidityData validity = ocspConfig.getValidity();
    Objects.requireNonNull(validity.getUnit());
    Objects.requireNonNull(validity.getAmount());
    Objects.requireNonNull(validity.getStartOffsetSec());

    ocspModel.setExpiryOffset(GeneralCAUtils.getDurationFromTypeAndValue(validity.getUnit(), validity.getAmount()));
    ocspModel.setStartOffset(Duration.ofSeconds(validity.getStartOffsetSec()));
    return ocspModel;
  }

  /**
   * Get the subject of the OCSP responder
   *
   * @param nameProperties name configuration properties
   * @return subject name model
   */
  protected CertNameModel<?> getSubjectNameModel(final EntityNameProperties nameProperties) {
    final List<AttributeTypeAndValueModel> attributes = new ArrayList<>();
    this.addAttributeToModel(nameProperties.getCountry(), CertAttributes.C, attributes);
    this.addAttributeToModel(nameProperties.getOrg(), CertAttributes.O, attributes);
    this.addAttributeToModel(nameProperties.getOrgUnit(), CertAttributes.OU, attributes);
    this.addAttributeToModel(nameProperties.getOrgIdentifier(), CertAttributes.ORGANIZATION_IDENTIFIER, attributes);
    this.addAttributeToModel(nameProperties.getSerialNumber(), CertAttributes.SERIALNUMBER, attributes);
    this.addAttributeToModel(nameProperties.getCommonName(), CertAttributes.CN, attributes);
    return new ExplicitCertNameModel(attributes);
  }

  private void addAttributeToModel(final String value, final ASN1ObjectIdentifier attrOid,
      final List<AttributeTypeAndValueModel> attributeList) {
    if (StringUtils.isNotBlank(value)) {
      attributeList.add(AttributeTypeAndValueModel.builder()
          .attributeType(attrOid)
          .value(value)
          .build());
    }
  }

  /**
   * Creates the CRL issuer model
   *
   * @param caConfig CA configuration properties
   * @param caCert Certificate of the issuing CA
   * @param distributionPointUrl URL where revocation list can be obtained
   * @param repository the repository for the CA
   * @param maxDurationBeforeCRLUpgrade
   * @return CRL issuer model
   */
  private CRLIssuerModel getCRLIssuerModel(final CAConfigData.CaConfig caConfig, final X509CertificateHolder caCert,
    final String distributionPointUrl,
    final CARepository repository, final Duration maxDurationBeforeCRLUpgrade) {
    final CAConfigData.ValidityData crlValidity = caConfig.getCrlValidity();
    final CRLIssuerModel crlIssuerModel = new CRLIssuerModel(
        caCert,
        caConfig.getAlgorithm(),
        Duration.ofHours(crlValidity.getAmount()),
        distributionPointUrl);

    if (crlValidity.getUnit() != CAConfigData.ValidityUnit.H) {
      crlIssuerModel
          .setExpiryOffset(GeneralCAUtils.getDurationFromTypeAndValue(crlValidity.getUnit(), crlValidity.getAmount()));
    }
    crlIssuerModel.setStartOffset(Duration.ofSeconds(crlValidity.getStartOffsetSec()));
    if (maxDurationBeforeCRLUpgrade != null) {
      log.debug("Setting max age before enforcing new CRL from CRL issuer to {}", maxDurationBeforeCRLUpgrade);
      crlIssuerModel.setMaxDurationBeforeCRLUpgrade(maxDurationBeforeCRLUpgrade);
    }
    return crlIssuerModel;
  }

  /**
   * Get the CA certificate issuer model
   *
   * @param caConfig CA configuration properties
   * @return CA certificate issuer model
   */
  private CertificateIssuerModel getCertificateIssuerModel(final CAConfigData.CaConfig caConfig)
      throws NoSuchAlgorithmException {
    final CAConfigData.ValidityData validity = caConfig.getValidity();
    final CertificateIssuerModel certIssuerModel = new CertificateIssuerModel(caConfig.getAlgorithm(), GeneralCAUtils
        .getDurationFromTypeAndValue(
            CAConfigData.ValidityUnit.Y, validity.getAmount()));
    certIssuerModel
        .setExpiryOffset(GeneralCAUtils.getDurationFromTypeAndValue(validity.getUnit(), validity.getAmount()));
    return certIssuerModel;
  }

  /**
   * Get Certificate chain from chain pem file
   *
   * @param chainPemFileName name of file containing the certificate chain in PEM format
   * @return list of certificates
   * @throws IOException data parsing error
   * @throws PKCSException Certificate error
   * @throws OperatorCreationException PEM parsing error
   */
  private List<X509CertificateHolder> getCertChainFromPemFile(final String chainPemFileName)
      throws IOException, PKCSException, OperatorCreationException {
    if (chainPemFileName == null) {
      return new ArrayList<>();
    }
    return BasicX509Utils.getPemObjects(new FileInputStream(chainPemFileName))
        .stream()
        .filter(o -> o instanceof X509CertificateHolder)
        .map(o -> (X509CertificateHolder) o)
        .collect(Collectors.toList());
  }

  /**
   * Get directory and create it if missing
   *
   * @param instanceDir parent directory
   * @param dirName directory name
   * @return File object representing the target directory
   */
  private File createOrLoadDir(final File instanceDir, final String dirName) {
    final File dirFile = new File(instanceDir, dirName);
    if (!dirFile.exists()) {
      dirFile.mkdirs();
    }
    return dirFile;
  }

  /**
   * Locate the file specified by parameters
   *
   * @param keyFolder directory where the file is located
   * @param suffix the ending of the target file name
   * @param confResource preconfigured resource location that overrides search in the provided directory
   * @return the first file in the directory that match the suffix or null if absent
   */
  private String locateFile(final File keyFolder, final String suffix, final String confResource) {
    if (confResource != null) {
      if (confResource.startsWith("classpath:")) {
        return this.getClass().getResource("/" + confResource.substring(10)).getFile();
      }
      if (confResource.startsWith("/")) {
        return confResource;
      }
    }
    return Arrays.stream(Objects.requireNonNull(keyFolder.listFiles((dir, name) -> name.endsWith(suffix))))
        .map(file -> file.getAbsolutePath())
        .findFirst()
        .orElse(null);
  }

  /**
   * Check if a CA service instance is initialized
   *
   * @param instance the name of the target instance
   * @return true if the CA instance is initialized
   */
  @Override
  public boolean isServiceInitialized(final String instance) {
    if (this.caServicesMap.containsKey(instance)) {
      final CAService caService = this.caServicesMap.get(instance);
      return caService.getCaCertificate() != null;
    }
    return false;
  }

  /**
   * Get a CA service instance
   *
   * @param instance instance identifying the CA service instance
   * @return CA service
   */
  @Override
  public CAService getCAService(final String instance) {
    return this.caServicesMap.containsKey(instance) ? this.caServicesMap.get(instance) : null;
  }

}
