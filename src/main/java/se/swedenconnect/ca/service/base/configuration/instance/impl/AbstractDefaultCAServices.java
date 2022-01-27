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

package se.swedenconnect.ca.service.base.configuration.instance.impl;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.context.ApplicationEventPublisher;
import se.swedenconnect.ca.engine.ca.attribute.CertAttributes;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
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
import se.swedenconnect.ca.service.base.configuration.BasicServiceConfig;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventEnum;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventFactory;
import se.swedenconnect.ca.service.base.configuration.audit.CAAuditEventData;
import se.swedenconnect.ca.service.base.configuration.instance.InstanceConfiguration;
import se.swedenconnect.ca.service.base.configuration.instance.ca.AbstractBasicCA;
import se.swedenconnect.ca.service.base.configuration.keys.BasicX509Utils;
import se.swedenconnect.ca.service.base.configuration.keys.LocalKeySource;
import se.swedenconnect.ca.service.base.configuration.properties.CAConfigData;
import se.swedenconnect.ca.service.base.configuration.properties.EntityNameProperties;
import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;
import java.util.stream.Collectors;

/**
 * This implementation of CA Services assumes a set file structure within an instances folder
 * Where each instance has its onw folder with the name of the instance key.
 * each instance folder have the following sub folders:
 * <ul>
 *   <li>keys</li>
 *   <li>certs</li>
 *   <li>repository</li>
 * </ul>
 *
 * <p>The "keys" folder contains the key or key store files used by this instance</p>
 * <p>The "certs" can hold 2 files "ca-cert-chain.pem" and "self-issued.crt"</p>
 * <p>The "repository folder holds any files related to the implementation of the CA repository</p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractDefaultCAServices extends AbstractCAServices {

  private File instancesDir;
  private Map<String, CAConfigData> instanceConfigMap;
  private Map<String, CAService> caServicesMap;
  private final PKCS11Provider pkcs11Provider;
  private final BasicServiceConfig basicServiceConfig;
  private final Map<String, CARepository> caRepositoryMap;
  private final ApplicationEventPublisher applicationEventPublisher;

  public AbstractDefaultCAServices(InstanceConfiguration instanceConfiguration, PKCS11Provider pkcs11Provider,
    BasicServiceConfig basicServiceConfig, Map<String, CARepository> caRepositoryMap, ApplicationEventPublisher applicationEventPublisher) {
    super(instanceConfiguration);
    this.applicationEventPublisher = applicationEventPublisher;
    this.pkcs11Provider = pkcs11Provider;
    this.basicServiceConfig = basicServiceConfig;
    this.instancesDir = new File(basicServiceConfig.getDataStoreLocation(), "instances");
    this.instanceConfigMap = instanceConfiguration.getInstanceConfigMap();
    this.caRepositoryMap = caRepositoryMap;
    caServicesMap = new HashMap<>();
    instanceConfigMap.keySet().forEach(instance -> {
      caServicesMap.put(instance, getCaService(instance));
    });
  }

  /**
   * Main function to create or reassemble a CA instance based on configuration properties
   *
   *  <p>Process to create a CA service instance is:</p>
   *  <ul>
   *    <li>Create key credentials which includes locating key and cert. If key is generated. Then clear all history data</li>
   *    <li>Locate and test CA certificate. If not found. Then issue a self issued CA certificate</li>
   *    <li>If OCSP is enabled then locate OCSP service certificate. If not found, then issue an OCSP certificate.
   *        finally create the OCSP service</li>
   *    <li>Assemble CAService</li>
   *  </ul>
   *
   * @param instance
   * @return
   */
  private CAService getCaService(String instance) {
    log.debug("Creating the CA instance {}", instance);

    try {
      // Extract config data
      CAConfigData caConfigData = instanceConfigMap.get(instance);
      CAConfigData.CaConfig caConfig = caConfigData.getCa();
      CAConfigData.KeySourceData caKeyConf = caConfig.getKeySource();
      CAConfigData.OCSPConfig ocspConfig = caConfigData.getOcsp();

      // Get key storage folders for this instance
      File instanceDir = new File(instancesDir, instance);
      File keyDir = createOrLoadDir(instanceDir, "keys");
      File certsDir = createOrLoadDir(instanceDir, "certs");
      File repositoryDir = createOrLoadDir(instanceDir, "repository");

      log.debug("Creating the local key store for the CA of instance {}", instance);
      LocalKeySource caKeySource = getKeySource(caKeyConf, keyDir, "ca",
        keyDir, certsDir, repositoryDir);

      // Locate any existing CA Certs
      String chainFileName = locateFile(certsDir, "chain.pem", null);
      List<X509CertificateHolder> caChain = getCertChainFromPemFile(chainFileName);
      log.debug("Found {} preconfigured certificates in the CA certificate chain", caChain.size());
      X509CertificateHolder caCert;
      if (caChain.isEmpty()) {
        // There is no chain stored on file. Generate and save new self issued CA cert
        log.debug("Generating new self signed certificate for instance {}", instance);
        caCert = generateSelfIssuedCaCert(caKeySource, caConfigData, instance, basicServiceConfig.getServiceUrl());

        //Create self-issued CA certificate issuance audit log event
        applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.selfSignedCACertIsssued,
          new CAAuditEventData(
            instance,
            Base64.toBase64String(caCert.getEncoded()),
            caCert.getSerialNumber(),
            caCert.getSubject().toString()
          ),null, AuditEventFactory.DEFAULT_AUDIT_PRINCIPAL));

        log.debug("Self signed CA cert issued for {}", caCert.getSubject().toString());
        caChain = Collections.singletonList(caCert);
        File chainFile = new File(certsDir, "ca-chain.pem");
        File selfIssuedCaCertFile = new File(certsDir, "ca-self-signed.crt");
        FileUtils.writeStringToFile(chainFile, BasicX509Utils.getPemCert(caCert.getEncoded()));
        FileUtils.writeStringToFile(selfIssuedCaCertFile, BasicX509Utils.getPemCert(caCert.getEncoded()));
        log.debug("Saved new self issued CA certificate to {}", chainFile.getAbsolutePath());
      }
      else {
        // We found a certificate chain for this CA. use that and select the first cert as CA certificate
        caCert = caChain.get(0);
        log.debug("Found pre-configured CA certificate for {}", caCert.getSubject().toString());
      }

      //Validate the CA certificate
      log.debug("Validating the CA certificate match against the CA signing key for instance {}", instance);
      validateCertAndKey(caKeySource, caCert);

      // As we validated that the first certificate is the CA certificate. Make sure that the rest of the chain is in order:
      caChain = BasicX509Utils.getOrderedCertList(caChain, caCert);
      if (log.isDebugEnabled()){
        log.debug("Final ordered chain for ca instance {} is {}", instance,
          String.join(", ", caChain.stream().map(x509CertificateHolder -> x509CertificateHolder.getSubject().toString()).collect(Collectors.toList()))
        );
      }

      // Create CRL service and CA repository
      CARepository caRepository = caRepositoryMap.get(instance);
      log.debug("Setting up CA Repository for instance {}", instance);
      String crlDistrPoint = basicServiceConfig.getServiceUrl() + "/crl/" + instance + ".crl";
      log.debug("Setting CRL distribution point for instance {} to {}", instance, crlDistrPoint);
      CRLIssuerModel crlIssuerModel = getCRLIssuerModel(caConfig, caCert, crlDistrPoint, caRepository);

      // Create CA service with repository and CRL service
      log.debug("Instantiating the CA Service with CRL issuer for instance {}", instance);
      CertificateIssuerModel certIssuerModel = getCertificateIssuerModel(caConfig);
      AbstractBasicCA caService = getBasicCaService(instance, caConfig.getType() ,caKeySource.getCredential().getPrivateKey(),
        caChain, caRepository, certIssuerModel, crlIssuerModel, Collections.singletonList(crlDistrPoint));

      // Get OCSP service
      log.debug("Setting up OCSP responder for instance {}", instance);
      CAConfigData.KeySourceData ocspKeyConf = ocspConfig.getKeySource();
      boolean ocspEnabled = ocspConfig.getEnabled();
      if (ocspEnabled) {
        // OCSP service is enabled for this CA. Get the configured key source
        log.debug("Setting up key source for OCSP responder {}", instance);
        LocalKeySource ocspKeySource = getKeySource(ocspKeyConf, keyDir, "ocsp");
        // Determine if the OCSP responder is a separate entity based on whether we found a separate OCSP responder key
        boolean separateOcspEntity = ocspKeySource != null;
        // Set initial values for the OCSP certificate chain and algorithm
        List<X509CertificateHolder> ocspServiceChain = new ArrayList<>(caChain);
        String ocspAlgorithm = caConfig.getAlgorithm();

        X509CertificateHolder ocspIssuerCert = null;
        if (separateOcspEntity) {
          log.debug("Setting up OCSP responder as separate entity with its own signing key");
          // OCSP provider is a separate entity. Get or generate the OCSP certificate and set algorithm to the OCSP configured algorithm
          ocspAlgorithm = ocspConfig.getAlgorithm();
          String ocspCertFileName = locateFile(certsDir, "ocsp.crt", null);

          if (ocspCertFileName == null) {
            log.debug("Found no preconfigured OCSP signer certificate. Issuing a new OCSP signer certificate");
            // No OCSP certificate file was found. Generate a new OCSP certificate and save it

            ocspIssuerCert = generateOcspCertificate(caKeySource, caCert, ocspKeySource.getCertificate().getPublicKey(),
              caConfigData, instance, basicServiceConfig.getServiceUrl());

            //Create OCSP certificate issuance audit log event
            applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.ocspCertificateIssued,
              new CAAuditEventData(
                instance,
                Base64.toBase64String(ocspIssuerCert.getEncoded()),
                ocspIssuerCert.getSerialNumber(),
                ocspIssuerCert.getSubject().toString()
              ),null, AuditEventFactory.DEFAULT_AUDIT_PRINCIPAL));

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
          log.debug("Setting up OCSP responder with issuer certificate containing {} certificates", ocspServiceChain.size());
          // Pick the first cert in the chain as the OCSP certificate
          ocspIssuerCert = ocspServiceChain.get(0);
          // Validate that this cert has the correct public key
          log.debug("Validating OCSP signing certificate match with OCSP signing key for instance {}", instance);
          validateCertAndKey(ocspKeySource, ocspIssuerCert);
        }
        else {
          log.debug("OCSP responder does not have its own signing key. Signing OCSP responses with CA key for instance {}", instance);
          // OCSP has no separate key source. Use the CA key source instead
          ocspKeySource = caKeySource;
        }

        // Now we have everything to create the OCSP service instance
        log.debug("Instantiating OCSP responder for instance {}", instance);
        OCSPModel ocspModel = getOCSPmodel(ocspServiceChain, caService.getCaCertificate(), ocspAlgorithm, ocspConfig);
        OCSPResponder ocspResponder = new RepositoryBasedOCSPResponder(ocspKeySource.getCredential().getPrivateKey(), ocspModel,
          caRepository);
        // Add the OCSP responder to the CA service
        log.debug("Adding OCSP responder to instance {}", instance);
        caService.setOcspResponder(ocspResponder);
        // Set the OCSP responder URL
        caService.setOcspResponderUrl(basicServiceConfig.getServiceUrl() + "/ocsp/" + instance);
        caService.setOcspCertificate(ocspIssuerCert);
        log.debug("Setting OCSP service URL for instance {} to {}", instance, caService.getOCSPResponderURL());
      } else {
        log.debug("OCSP responder disabled for instance {}", instance);
      }

      log.info("Setup of CA Service instance {} completed", instance);

      return caService;
    }
    catch (Exception ex) {
      // Catching any error here represents a fatal error in the CA configuration setup.
      log.error("Failure to create CA instance {}", instance, ex);
      return null;
    }

  }

  /**
   * Creates an instance of a Basic CA Service
   * @param instance the instance of the CA being created
   * @param privateKey private key
   * @param caChain CA Certificate chain with the CA certificate as the first certificate in the list
   * @param caRepository CA Repository
   * @param certIssuerModel Certificate issuance model
   * @param crlIssuerModel CRL issuer model
   * @param crlDistributionPoints CRL Distribution point URL list
   * @return Basic CA Service instance
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   */
  protected abstract AbstractBasicCA getBasicCaService(String instance, String type, PrivateKey privateKey, List<X509CertificateHolder> caChain,
    CARepository caRepository, CertificateIssuerModel certIssuerModel, CRLIssuerModel crlIssuerModel, List<String> crlDistributionPoints)
    throws NoSuchAlgorithmException;

  /**
   * Allows the implementation of this abstract class to modify the content of the OCSP certificate
   *
   * @param certModelBuilder
   */
  protected abstract void customizeOcspCertificateModel(DefaultCertificateModelBuilder certModelBuilder, String instance);

  protected X509CertificateHolder generateOcspCertificate(LocalKeySource caKeySource, X509CertificateHolder issuerCert,
    PublicKey ocspPublicKey, CAConfigData caConfigData, String instance, String baseUrl)
    throws NoSuchAlgorithmException, IOException {
    CAConfigData.CaConfig caConfig = caConfigData.getCa();
    if (caConfig.getSelfIssuedValidYears() == null) {
      log.error("Illegal self issued validity configuration");
      throw new RuntimeException("Illegal self issued validity configuration - null");
    }
    CAConfigData.OCSPConfig ocspConfig = caConfigData.getOcsp();

    CAConfigData.ValidityData validity = caConfig.getValidity();
    int validityAmount = validity.getAmount();
    Integer ocspCertValidityAmount = caConfig.getOcspCertValidityAmount();
    if (ocspCertValidityAmount != null && ocspCertValidityAmount > 0){
      validityAmount = ocspCertValidityAmount;
    }
    CertificateIssuerModel certificateIssuerModel = new CertificateIssuerModel(caConfig.getAlgorithm(), validityAmount);
    certificateIssuerModel.setExpiryOffsetType(validity.getUnit().getUnitType());
    certificateIssuerModel.setStartOffsetAmount(validity.getStartOffsetSec());

    CertificateIssuer issuer = new BasicCertificateIssuer(certificateIssuerModel,issuerCert.getSubject(), caKeySource.getCredential().getPrivateKey());
    DefaultCertificateModelBuilder certModelBuilder = DefaultCertificateModelBuilder.getInstance(
      ocspPublicKey, issuerCert, certificateIssuerModel)
      .subject(getSubjectNameModel(ocspConfig.getName()))
      .basicConstraints(new BasicConstraintsModel(false, false))
      .includeAki(true)
      .includeSki(true)
      .keyUsage(new KeyUsageModel(KeyUsage.digitalSignature))
      .ocspNocheck(true)
      .extendedKeyUsage(new ExtendedKeyUsageModel(true, KeyPurposeId.id_kp_OCSPSigning));

    // Allow the implementation of this abstract class to modify the OCSP certificate content
    customizeOcspCertificateModel(certModelBuilder, instance);
    return issuer.issueCertificate(certModelBuilder.build());
  }

  /**
   * Generate self issued certificate. Note that this function does NOT engage the CA repository as the self issued certificate
   * is not a trusted certificate and not part of the certificates issued and maintained by this CA, and as such can never be revoked.
   *
   * <p>Implementations of this function are supposed to create a CertificateIssuerInstance with the key of the CA and simply
   * create a self signed certificate that can be used initially as the CA certificate of this CA service</p>
   *
   * @param caKeySource  CA key source
   * @param caConfigData CA configuration properties
   * @param instance     The instance identifier
   * @return self issued certificate
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   */
  protected abstract X509CertificateHolder generateSelfIssuedCaCert(LocalKeySource caKeySource, CAConfigData caConfigData, String instance, String baseUrl)
    throws NoSuchAlgorithmException;

  /**
   * Default implementation of the self issued cert generation that may be used when implementing the generateSelfIssuedCaCert abstract method
   *
   * @param caKeySource  CA key source
   * @param caConfigData CA configuration properties
   * @return self issued certificate
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   */
  protected X509CertificateHolder defaultGenerateSelfIssuedCaCert(LocalKeySource caKeySource, CAConfigData caConfigData)
    throws NoSuchAlgorithmException {
    CAConfigData.CaConfig caConfig = caConfigData.getCa();
    if (caConfig.getSelfIssuedValidYears() == null) {
      log.error("Illegal self issued validity configuration");
      throw new RuntimeException("Illegal self issued validity configuration - null");
    }

    CertificateIssuerModel certificateIssuerModel = new CertificateIssuerModel(
      caConfig.getAlgorithm(),
      caConfig.getSelfIssuedValidYears()
    );
    CertificateIssuer issuer = new SelfIssuedCertificateIssuer(certificateIssuerModel);
    CertificateModel certModel = SelfIssuedCertificateModelBuilder.getInstance(
      caKeySource.getCredential().getPrivateKey(),
      caKeySource.getCertificate().getPublicKey(),
      certificateIssuerModel)
      .subject(getSubjectNameModel(caConfig.getName()))
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
   * @param keySource   key source
   * @param certificate certificate for the public key of the key source
   * @throws IOException on error in the input data
   */
  private void validateCertAndKey(LocalKeySource keySource, X509CertificateHolder certificate) throws IOException {
    assert keySource != null;
    boolean caCertKeyMatch = Arrays.equals(
      Objects.requireNonNull(keySource.getCredential().getPublicKey()).getEncoded(),
      certificate.getSubjectPublicKeyInfo().getEncoded()
    );
    if (!caCertKeyMatch) {
      throw new IOException("Configured CA certificate does not match configured CA key");
    }
  }

  /**
   * Gets a key source based on configuration data.
   *
   * <p>The certificate used in the key source is a dummy certificate in the context of the CA. It is a certificate
   * created when generating the key that is necessary to match the current PKCS#11 implementation library.
   * This certificate is not used as CA or OCSP certificate as those certificates are created and stored separately</p>
   *
   * @param keyConf          key configuration data from properties settings of this key
   * @param keyDir           the directory where key and key cert files are located
   * @param entityIdentifier a prefix that must occur before the file extension of relevant key resource files
   * @param cleanDirs        a list of directories that should be wiped of all content if this key is created from sratch to delete history of old key
   * @return key source
   */
  private LocalKeySource getKeySource(CAConfigData.KeySourceData keyConf, File keyDir, String entityIdentifier, File... cleanDirs) {
    String keyLocation = null;
    String certLocation = null;
    switch (keyConf.getType()) {
    case none:
      return null;
    case create:
      for (File file : cleanDirs) {
        try {
          FileUtils.cleanDirectory(file);
        }
        catch (IOException e) {
          log.error("Failed to delete configured directory {}", file.getAbsolutePath(), e);
        }
      }
      break;
    case jks:
      keyLocation = locateFile(keyDir, entityIdentifier + ".jks", keyConf.getResource());
      break;
    case pem:
    case pkcs11:
      //keyLocation = locateFile(keyDir, entityIdentifier + ".key", null);
      certLocation = locateFile(keyDir, entityIdentifier + ".crt", null);
      break;
    case pkcs12:
      keyLocation = locateFile(keyDir, entityIdentifier + ".p12", keyConf.getResource());
      break;
    }

    return new LocalKeySource(keyConf.getType().name(),
      keyLocation, keyConf.getPass(), keyConf.getAlias(), certLocation, pkcs11Provider, keyConf.getReloadableKeys());
  }

  /**
   * Setup the OCSP model
   *
   * @param ocspServiceChain certificate chain for the OCSP responder
   * @param caCertificate    CA certificate used to issue the certificates that are checked for revocation
   * @param ocspAlgorithm    the algorithm URI representing the OCSP response signing algorithm
   * @param ocspConfig       configuration data for the OCSP responder
   * @return OCSP model
   */
  private OCSPModel getOCSPmodel(List<X509CertificateHolder> ocspServiceChain, X509CertificateHolder caCertificate, String ocspAlgorithm,
    CAConfigData.OCSPConfig ocspConfig) {
    OCSPModel ocspModel = new OCSPModel(ocspServiceChain, caCertificate, ocspAlgorithm);

    CAConfigData.ValidityData validity = ocspConfig.getValidity();
    if (validity.getUnit() != null) {
      ocspModel.setExpiryOffsetType(validity.getUnit().getUnitType());
    }
    ocspModel.setExpiryOffsetAmount(validity.getAmount());
    ocspModel.setStartOffsetType(Calendar.SECOND);
    ocspModel.setStartOffsetAmount(validity.getStartOffsetSec());
    return ocspModel;
  }

  /**
   * Get the subject of the OCSP responder
   *
   * @param nameProperties name configuration properties
   * @return subject name model
   */
  protected CertNameModel getSubjectNameModel(EntityNameProperties nameProperties) {
    List<AttributeTypeAndValueModel> attributes = new ArrayList<>();
    addAttributeToModel(nameProperties.getCountry(), CertAttributes.C, attributes);
    addAttributeToModel(nameProperties.getOrg(), CertAttributes.O, attributes);
    addAttributeToModel(nameProperties.getOrgUnit(), CertAttributes.OU, attributes);
    addAttributeToModel(nameProperties.getOrgIdentifier(), CertAttributes.ORGANIZATION_IDENTIFIER, attributes);
    addAttributeToModel(nameProperties.getSerialNumber(), CertAttributes.SERIALNUMBER, attributes);
    addAttributeToModel(nameProperties.getCommonName(), CertAttributes.CN, attributes);
    return new ExplicitCertNameModel(attributes);
  }

  private void addAttributeToModel(String value, ASN1ObjectIdentifier attrOid, List<AttributeTypeAndValueModel> attributeList) {
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
   * @param caConfig             CA configuration properties
   * @param caCert               Certificate of the issuing CA
   * @param distributionPointUrl URL where revocation list can be obtained
   * @param repository           the repository for the CA
   * @return CRL issuer model
   */
  private CRLIssuerModel getCRLIssuerModel(CAConfigData.CaConfig caConfig, X509CertificateHolder caCert, String distributionPointUrl,
    CARepository repository) {
    CAConfigData.ValidityData crlValidity = caConfig.getCrlValidity();
    CRLIssuerModel crlIssuerModel = new CRLIssuerModel(
      caCert,
      caConfig.getAlgorithm(),
      crlValidity.getAmount(),
      repository.getCRLRevocationDataProvider(),
      distributionPointUrl);

    if (crlValidity.getUnit() != CAConfigData.ValidityUnit.H) {
      crlIssuerModel.setExpiryOffsetType(crlValidity.getUnit().getUnitType());
    }
    crlIssuerModel.setStartOffsetAmount(crlValidity.getStartOffsetSec());
    return crlIssuerModel;
  }

  /**
   * Get the CA certificate issuer model
   *
   * @param caConfig CA configuration properties
   * @return CA certificate issuer model
   */
  private CertificateIssuerModel getCertificateIssuerModel(CAConfigData.CaConfig caConfig) throws NoSuchAlgorithmException {
    CAConfigData.ValidityData validity = caConfig.getValidity();
    CertificateIssuerModel certIssuerModel = new CertificateIssuerModel(caConfig.getAlgorithm(), validity.getAmount());
    certIssuerModel.setExpiryOffsetType(validity.getUnit().getUnitType());
    certIssuerModel.setStartOffsetAmount(validity.getStartOffsetSec());
    return certIssuerModel;
  }

  /**
   * Get Certificate chain from chain pem file
   *
   * @param chainPemFileName name of file containing the certificate chain in PEM format
   * @return list of certificates
   * @throws IOException               data parsing error
   * @throws PKCSException             Certificate error
   * @throws OperatorCreationException PEM parsing error
   */
  private List<X509CertificateHolder> getCertChainFromPemFile(String chainPemFileName)
    throws IOException, PKCSException, OperatorCreationException {
    if (chainPemFileName == null) {
      return new ArrayList<>();
    }
    return BasicX509Utils.getPemObjects(new FileInputStream(chainPemFileName)).stream()
      .filter(o -> o instanceof X509CertificateHolder)
      .map(o -> (X509CertificateHolder) o)
      .collect(Collectors.toList());
  }

  /**
   * Get directory and create it if missing
   *
   * @param instanceDir parent directory
   * @param dirName     directory name
   * @return File object representing the target directory
   */
  private File createOrLoadDir(File instanceDir, String dirName) {
    File dirFile = new File(instanceDir, dirName);
    if (!dirFile.exists()) {
      dirFile.mkdirs();
    }
    return dirFile;
  }

  /**
   * Locate the file specified by parameters
   *
   * @param keyFolder directory where the file is located
   * @param suffix    the ending of the target file name
   * @param confResource preconfigured resource location that overrides search in the provided directory
   * @return the first file in the directory that match the suffix or null if absent
   */
  private String locateFile(File keyFolder, String suffix, String confResource) {
    if (confResource != null) {
      if (confResource.startsWith("classpath:")){
        return getClass().getResource("/" + confResource.substring(10)).getFile();
      }
      if (confResource.startsWith("/")){
        return confResource;
      }
    }
    return Arrays.stream(Objects.requireNonNull(keyFolder.listFiles((dir, name) -> name.endsWith(suffix))))
      .map(file -> file.getAbsolutePath()).findFirst().orElse(null);
  }

  /**
   * Check if a CA service instance is initialized
   *
   * @param instance the name of the target instance
   * @return true if the CA instance is initialized
   */
  @Override public boolean isServiceInitialized(String instance) {
    if (caServicesMap.containsKey(instance)) {
      CAService caService = caServicesMap.get(instance);
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
  @Override public CAService getCAService(String instance) {
    return caServicesMap.containsKey(instance) ? caServicesMap.get(instance) : null;
  }

}
