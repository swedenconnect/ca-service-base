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
package se.swedenconnect.ca.service.base.configuration.health;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.service.base.ca.CAServices;
import se.swedenconnect.ca.service.base.ca.impl.AbstractBasicCA;
import se.swedenconnect.ca.service.base.configuration.BasicServiceConfig;
import se.swedenconnect.ca.service.base.configuration.instance.InstanceConfiguration;
import se.swedenconnect.ca.service.base.configuration.keys.BasicX509Utils;
import se.swedenconnect.ca.service.base.configuration.properties.CAConfigData;
import se.swedenconnect.ca.service.base.utils.GeneralCAUtils;

/**
 * Service information Bean building the service information about the CA service.
 */
@Slf4j
@Configuration
public class ServiceInfo {

  /** Milliseconds in a week */
  private static final long WEEK_MILLISECONDS = 1000 * 60 * 60 * 24 * 7;

  /** Information about the CA service */
  private CAServiceInfo caServiceInfo;

  @Value("${server.servlet.context-path:#{null}}")
  String servicePath;

  @Value("${tomcat.ajp.enabled}")
  boolean ajpEnabled;

  @Value("${tomcat.ajp.port}")
  int ajpPort;

  @Value("${tomcat.ajp.secret}")
  String ajpSecret;

  @Value("${server.port}")
  int servicePort;

  @Value("${management.server.port}")
  int managePort;

  @Value("${ca-service.config.control-port}")
  int adminPort;

  private final BasicServiceConfig basicServiceConfig;
  private final CAServices caServices;
  private final InstanceConfiguration instanceConfig;

  /**
   * Bean constructor for Service information.
   *
   * @param basicServiceConfig basic service configuration data
   * @param caServices ca services
   * @param instanceConfig CA instance configuration
   */
  @Autowired
  public ServiceInfo(final BasicServiceConfig basicServiceConfig, final CAServices caServices,
      final InstanceConfiguration instanceConfig) {
    this.basicServiceConfig = basicServiceConfig;
    this.caServices = caServices;
    this.instanceConfig = instanceConfig;
    this.caServiceInfo = new CAServiceInfo();
  }

  /**
   * Returns the collected proxy service information.
   *
   * @return Proxy Service information
   */
  public CAServiceInfo getCaServiceInfo() {
    this.collectServiceInfo();
    return this.caServiceInfo;
  }

  /**
   * Test the configuration data.
   *
   * @throws RuntimeException This exception is thrown if an error is found. The nature of the error is provided in the
   *           exception message.
   */
  public void testConfiguration() throws RuntimeException {
    this.collectServiceInfo();
    // Test basic parameters
    if (!StringUtils.hasText(this.caServiceInfo.getContextPath())) {
      log.debug("Service context path is not specified - Allowed configuration");
    }

    if (!StringUtils.hasText(this.caServiceInfo.getServiceUrl())) {
      throw new IllegalArgumentException("Service URL is not specified");
    }

    final List<CAServiceInfo.CAInstanceInfo> caInstances = this.caServiceInfo.getCaInstances();
    if (caInstances == null || caInstances.isEmpty()) {
      throw new IllegalArgumentException("No CA service instances are configured");
    }

    for (final CAServiceInfo.CAInstanceInfo caInstanceInfo : caInstances) {
      final String instance = caInstanceInfo.getId();
      if (!StringUtils.hasText(caInstanceInfo.getKeySourceType())) {
        throw new IllegalArgumentException("CA key source type is undefined for instance " + instance);
      }

      final CAServiceInfo.KeyInfo keyInfo = caInstanceInfo.getKeyInfo();
      if (keyInfo == null) {
        throw new IllegalArgumentException("No CA key present for instance " + instance);
      }
      else {
        if (keyInfo.getKeyType() == null) {
          throw new IllegalArgumentException("Illegal key type for instance " + instance);
        }
        switch (keyInfo.getKeyType().toUpperCase()) {
        case "RSA":
          if (keyInfo.getKeyLength() < 2048) {
            throw new IllegalArgumentException("RSA key for instance " + instance + " is less than 2048 bit");
          }
          break;
        case "EC":
          if (keyInfo.getKeyLength() < 256) {
            throw new IllegalArgumentException("EC key for instance " + instance + " is less than 256 bit");
          }
          break;
        default:
          throw new IllegalArgumentException("Illegal key type for instance " + instance);
        }
      }

      if (!StringUtils.hasText(caInstanceInfo.getAlgorithm())) {
        throw new IllegalArgumentException("No algorithm specified for instance " + instance);
      }
      if (!StringUtils.hasText(caInstanceInfo.getDn())) {
        throw new IllegalArgumentException("No CA certificate is specified for instance " + instance);
      }

      if (caInstanceInfo.isOscpEnabled()) {
        final CAServiceInfo.OCSPInfo ocspInfo = caInstanceInfo.getOcspInfo();
        if (!StringUtils.hasText(ocspInfo.getOcspServiceUrl())) {
          throw new IllegalArgumentException("No OCSP service URL is specified for instance " + instance);
        }
        if (ocspInfo.isSeparateEntity()) {
          ocspInfo.getOcspEntity();
          this.caServices.getCAService(instance).getOCSPResponder();
          X509CertificateHolder ocspCert = null;
          try {
            ocspCert = GeneralCAUtils.getOcspCert(this.basicServiceConfig.getDataStoreLocation(), instance);
          }
          catch (final Exception ex) {
            throw new RuntimeException("unable to parse OCSP certificate: " + ex.getMessage());
          }
          final Date ocspCertNotAfter = ocspCert.getNotAfter();
          final Date currentTime = new Date();
          final Date aWeekFromNow = new Date(System.currentTimeMillis() + WEEK_MILLISECONDS);
          if (ocspCertNotAfter.before(currentTime)) {
            throw new IllegalArgumentException("The OCSP certificate has expired");
          }
          if (ocspCertNotAfter.before(aWeekFromNow)) {
            final ServiceHealthWarningException warning =
                new ServiceHealthWarningException("The OCSP certificate will expire soon");
            warning.addDetail("expiryDate:", ocspCertNotAfter);
            warning.addDetail("ocspIssuer: ", ocspCert.getSubject().toString());
            throw warning;
          }

        }

      }

    }

  }

  private void collectServiceInfo() {
    // General info
    this.caServiceInfo = CAServiceInfo.builder()

        .contextPath(this.servicePath)
        .serviceUrl(this.basicServiceConfig.getServiceUrl())
        .servicePort(this.servicePort)
        .adminPort(this.adminPort)
        .managePort(this.managePort)
        .ajpConfig(
            this.ajpEnabled ? new CAServiceInfo.AJPInfo(this.ajpPort, StringUtils.hasText(this.ajpSecret)) : null)
        .caInstances(this.getCAInstancesInfo())
        .build();
  }

  private List<CAServiceInfo.CAInstanceInfo> getCAInstancesInfo() {
    final List<CAServiceInfo.CAInstanceInfo> caInstanceInfoList = new ArrayList<>();
    final Map<String, CAConfigData> caConfigDataMap = this.instanceConfig.getInstanceConfigMap();

    if (caConfigDataMap == null) {
      return caInstanceInfoList;
    }

    final List<String> instances = new ArrayList<>(caConfigDataMap.keySet());

    for (final String instance : instances) {
      // Extract all information about this instance;
      final CAConfigData caConfigData = caConfigDataMap.get(instance);
      final CAConfigData.CaConfig caConfig = caConfigData.getCa();
      final CAConfigData.OCSPConfig ocspConfig = caConfigData.getOcsp();
      if (!this.getBoolean(caConfigData.getEnabled())) {
        caInstanceInfoList.add(CAServiceInfo.CAInstanceInfo.builder().enabled(false).build());
        continue;
      }
      final CAService caService = this.caServices.getCAService(instance);
      final List<String> dnList = this.getDnList(instance);
      final X509CertificateHolder ocspCert = this.getOcspCert(instance);
      List<String> crlDistributionPoints = new ArrayList<>();
      String ocspResponderUrl = null;
      if (caService instanceof AbstractBasicCA) {
        final AbstractBasicCA basicCAService = (AbstractBasicCA) caService;
        crlDistributionPoints = basicCAService.getCrlDistributionPoints();
        ocspResponderUrl = basicCAService.getOCSPResponderURL();
      }

      // Store info
      caInstanceInfoList.add(CAServiceInfo.CAInstanceInfo.builder()
          .id(instance)
          .enabled(true)
          .serviceType(caConfig.getType())
          .caPath(dnList)
          .dn(caService.getCaCertificate().getSubject().toString())
          .crlDistributionPoints(crlDistributionPoints)
          .algorithm(caConfig.getAlgorithm())
          .keySourceType(caConfig.getKeySource().getType().name())
          .keyInfo(this.getKeyInfoData(caService.getCaCertificate()))
          .oscpEnabled(this.getBoolean(ocspConfig.getEnabled()))
          .ocspInfo(this.getOcspInfo(ocspConfig, ocspResponderUrl, ocspCert))
          .build());
    }
    return caInstanceInfoList;
  }

  private CAServiceInfo.OCSPInfo getOcspInfo(final CAConfigData.OCSPConfig ocspConfig, final String ocspServiceUrl,
      final X509CertificateHolder ocspCert) {
    final CAServiceInfo.OCSPInfo.OCSPInfoBuilder builder = CAServiceInfo.OCSPInfo.builder();
    if (ocspConfig == null || !this.getBoolean(ocspConfig.getEnabled())) {
      return null;
    }
    final CAConfigData.KeySourceData keySource = ocspConfig.getKeySource();
    builder
        .ocspServiceUrl(ocspServiceUrl)
        .separateEntity(ocspCert != null);

    if (ocspCert != null) {
      builder
          .ocspEntity(CAServiceInfo.OCSPEntityInfo.builder()
              .dn(ocspCert.getSubject().toString())
              .keySourceType(keySource.getType().name())
              .algorithm(ocspConfig.getAlgorithm())
              .keyInfo(this.getKeyInfoData(ocspCert))
              .build());
    }
    return builder.build();
  }

  private CAServiceInfo.KeyInfo getKeyInfoData(final X509CertificateHolder ocspCert) {
    int keyLen = -1;
    String keyType = null;
    try {
      final PublicKey publicKey = BouncyCastleProvider.getPublicKey(ocspCert.getSubjectPublicKeyInfo());
      keyLen = BasicX509Utils.getKeyLength(publicKey);
      if (publicKey instanceof ECPublicKey) {
        keyType = "EC";
      }
      if (publicKey instanceof RSAPublicKey) {
        keyType = "RSA";
      }
      return new CAServiceInfo.KeyInfo(keyType, keyLen);
    }
    catch (final IOException ignored) {
    }
    return null;
  }

  private X509CertificateHolder getOcspCert(final String instance) {
    try {
      final File instanceDir = this.getInstanceDir(instance);
      final File certsDir = new File(instanceDir, "certs");
      final File ocspCert = new File(certsDir, "ocsp.crt");

      return new JcaX509CertificateHolder(
          Objects.requireNonNull(
              BasicX509Utils.getCertOrNull(
                  FileUtils.readFileToByteArray(
                      ocspCert))));
    }
    catch (final Exception ex) {
      return null;
    }
  }

  private List<String> getDnList(final String instance) {
    try {
      final File instanceDir = this.getInstanceDir(instance);
      final File certsDir = new File(instanceDir, "certs");
      final File chainFile = new File(certsDir, "ca-chain.pem");
      FileUtils.readFileToByteArray(chainFile);
      return BasicX509Utils.getPemObjects(new FileInputStream(chainFile)).stream()
          .filter(o -> o instanceof X509CertificateHolder)
          .map(o -> (X509CertificateHolder) o)
          .map(x509CertificateHolder -> x509CertificateHolder.getSubject().toString())
          .collect(Collectors.toList());
    }
    catch (final Exception ex) {
      return null;
    }
  }

  private File getInstanceDir(final String instance) {
    this.caServices.getCAService(instance);
    final File instancesDir = new File(this.basicServiceConfig.getDataStoreLocation(), "instances");
    final File instanceDir = new File(instancesDir, instance);
    return instanceDir;
  }

  private boolean getBoolean(final Boolean booleanObject) {
    return booleanObject == null ? false : booleanObject;
  }

}
