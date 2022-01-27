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

package se.swedenconnect.ca.service.base.configuration.health;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.ca.service.base.configuration.BasicServiceConfig;
import se.swedenconnect.ca.service.base.configuration.instance.CAServices;
import se.swedenconnect.ca.service.base.configuration.instance.InstanceConfiguration;
import se.swedenconnect.ca.service.base.configuration.instance.ca.AbstractBasicCA;
import se.swedenconnect.ca.service.base.configuration.keys.BasicX509Utils;
import se.swedenconnect.ca.service.base.configuration.properties.CAConfigData;
import se.swedenconnect.ca.service.base.utils.GeneralCAUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service information Bean
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Configuration
public class ServiceInfo {

  private static final long WEEK_MILLISECONDS = 1000 * 60 * 60 * 24 * 7;

  private CAServiceInfo caServiceInfo;

  @Value("${server.servlet.context-path:#{null}}") String servicePath;
  @Value(("${tomcat.ajp.enabled}")) boolean ajpEnabled;
  @Value(("${tomcat.ajp.port}")) int ajpPort;
  @Value(("${tomcat.ajp.secret}")) String ajpSecret;
  @Value(("${server.port}")) int servicePort;
  @Value(("${management.server.port}")) int managePort;
  @Value(("${ca-service.config.control-port}")) int adminPort;

  private final BasicServiceConfig basicServiceConfig;
  private final CAServices caServices;
  private final InstanceConfiguration instanceConfig;

  @Autowired
  public ServiceInfo(BasicServiceConfig basicServiceConfig, CAServices caServices,
    InstanceConfiguration instanceConfig) {
    this.basicServiceConfig = basicServiceConfig;
    this.caServices = caServices;
    this.instanceConfig = instanceConfig;
    this.caServiceInfo = new CAServiceInfo();
  }

  /**
   * Returns the collected proxy service information
   *
   * @return Proxy Service information
   */
  public CAServiceInfo getCaServiceInfo() {
    collectServiceInfo();
    return caServiceInfo;
  }

  /**
   * Test the configuration data
   *
   * @throws RuntimeException This exception is thrown if an error is found. The nature of the error is provided in the exception message.
   */
  public void testConfiguration() throws RuntimeException {
    collectServiceInfo();
    //Test basic parameters
    if (!StringUtils.hasText(caServiceInfo.getContextPath())) {
      throw new IllegalArgumentException("Service context path is not specified");
    }

    if (!StringUtils.hasText(caServiceInfo.getServiceUrl())) {
      throw new IllegalArgumentException("Service URL is not specified");
    }

    List<CAServiceInfo.CAInstanceInfo> caInstances = caServiceInfo.getCaInstances();
    if (caInstances == null || caInstances.isEmpty()) {
      throw new IllegalArgumentException("No CA service instances are configured");
    }

    for (CAServiceInfo.CAInstanceInfo caInstanceInfo : caInstances) {
      String instance = caInstanceInfo.getId();
      if (!StringUtils.hasText(caInstanceInfo.getKeySourceType())) {
        throw new IllegalArgumentException("CA key source type is undefined for instance " + instance);
      }

      CAServiceInfo.KeyInfo keyInfo = caInstanceInfo.getKeyInfo();
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
        CAServiceInfo.OCSPInfo ocspInfo = caInstanceInfo.getOcspInfo();
        if (!StringUtils.hasText(ocspInfo.getOcspServiceUrl())) {
          throw new IllegalArgumentException("No OCSP service URL is specified for instance " + instance);
        }
        if (ocspInfo.isSeparateEntity()) {
          CAServiceInfo.OCSPEntityInfo ocspEntity = ocspInfo.getOcspEntity();
          OCSPResponder ocspResponder = caServices.getCAService(instance).getOCSPResponder();
          X509CertificateHolder ocspCert = null;
          try {
            ocspCert = GeneralCAUtils.getOcspCert(basicServiceConfig.getDataStoreLocation(), instance);
          } catch (Exception ex) {
            throw new RuntimeException("unable to parse OCSP certificate: " + ex.getMessage());
          }
          Date ocspCertNotAfter = ocspCert.getNotAfter();
          Date currentTime = new Date();
          Date aWeekFromNow = new Date(System.currentTimeMillis() + WEEK_MILLISECONDS);
          if (ocspCertNotAfter.before(currentTime)){
            throw new IllegalArgumentException("The OCSP certificate has expired");
          }
          if (ocspCertNotAfter.before(aWeekFromNow)){
            ServiceHealthWarningException warning = new ServiceHealthWarningException("The OCSP certificate will expire soon");
            warning.addDetail("expiryDate:", ocspCertNotAfter);
            warning.addDetail("ocspIssuer: ", ocspCert.getSubject().toString());
            throw warning;
          }

        }

      }

    }

  }

  private void collectServiceInfo() {
    //General info
    this.caServiceInfo = CAServiceInfo.builder()

      .contextPath(servicePath)
      .serviceUrl(basicServiceConfig.getServiceUrl())
      .servicePort(servicePort)
      .adminPort(adminPort)
      .managePort(managePort)
      .ajpConfig(ajpEnabled ? new CAServiceInfo.AJPInfo(ajpPort, StringUtils.hasText(ajpSecret)) : null)
      .caInstances(getCAInstancesInfo())
      .build();
  }

  private List<CAServiceInfo.CAInstanceInfo> getCAInstancesInfo() {
    List<CAServiceInfo.CAInstanceInfo> caInstanceInfoList = new ArrayList<>();
    Map<String, CAConfigData> caConfigDataMap = instanceConfig.getInstanceConfigMap();

    if (caConfigDataMap == null) {
      return caInstanceInfoList;
    }

    List<String> instances = new ArrayList<>(caConfigDataMap.keySet());

    for (String instance : instances) {
      // Extract all information about this instance;
      CAConfigData caConfigData = caConfigDataMap.get(instance);
      CAConfigData.CaConfig caConfig = caConfigData.getCa();
      CAConfigData.OCSPConfig ocspConfig = caConfigData.getOcsp();
      if (!getBoolean(caConfigData.getEnabled())) {
        caInstanceInfoList.add(CAServiceInfo.CAInstanceInfo.builder().enabled(false).build());
        continue;
      }
      CAService caService = caServices.getCAService(instance);
      List<String> dnList = getDnList(instance);
      X509CertificateHolder ocspCert = getOcspCert(instance);
      List<String> crlDistributionPoints = new ArrayList<>();
      String ocspResponderUrl = null;
      if (caService instanceof AbstractBasicCA) {
        AbstractBasicCA basicCAService = (AbstractBasicCA) caService;
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
        .keyInfo(getKeyInfoData(caService.getCaCertificate()))
        .oscpEnabled(getBoolean(ocspConfig.getEnabled()))
        .ocspInfo(getOcspInfo(ocspConfig, ocspResponderUrl, ocspCert))
        .build());
    }
    return caInstanceInfoList;
  }

  private CAServiceInfo.OCSPInfo getOcspInfo(CAConfigData.OCSPConfig ocspConfig, String ocspServiceUrl, X509CertificateHolder ocspCert) {
    CAServiceInfo.OCSPInfo.OCSPInfoBuilder builder = CAServiceInfo.OCSPInfo.builder();
    if (ocspConfig == null || !getBoolean(ocspConfig.getEnabled())) {
      return null;
    }
    CAConfigData.KeySourceData keySource = ocspConfig.getKeySource();
    builder
      .ocspServiceUrl(ocspServiceUrl)
      .separateEntity(ocspCert != null);

    if (ocspCert != null) {
      builder
        .ocspEntity(CAServiceInfo.OCSPEntityInfo.builder()
          .dn(ocspCert.getSubject().toString())
          .keySourceType(keySource.getType().name())
          .algorithm(ocspConfig.getAlgorithm())
          .keyInfo(getKeyInfoData(ocspCert))
          .build()
        );
    }
    return builder.build();
  }

  private CAServiceInfo.KeyInfo getKeyInfoData(X509CertificateHolder ocspCert) {
    int keyLen = -1;
    String keyType = null;
    try {
      PublicKey publicKey = BouncyCastleProvider.getPublicKey(ocspCert.getSubjectPublicKeyInfo());
      keyLen = BasicX509Utils.getKeyLength(publicKey);
      if (publicKey instanceof ECPublicKey)
        keyType = "EC";
      if (publicKey instanceof RSAPublicKey)
        keyType = "RSA";
      return new CAServiceInfo.KeyInfo(keyType, keyLen);
    }
    catch (IOException ignored) {
    }
    return null;
  }

  private X509CertificateHolder getOcspCert(String instance) {
    try {
      File instanceDir = getInstanceDir(instance);
      File certsDir = new File(instanceDir, "certs");
      File ocspCert = new File(certsDir, "ocsp.crt");

      return new JcaX509CertificateHolder(
        Objects.requireNonNull(
          BasicX509Utils.getCertOrNull(
            FileUtils.readFileToByteArray(
              ocspCert))));
    }
    catch (Exception ex) {
      return null;
    }
  }

  private List<String> getDnList(String instance) {
    try {
      File instanceDir = getInstanceDir(instance);
      File certsDir = new File(instanceDir, "certs");
      File chainFile = new File(certsDir, "ca-chain.pem");
      FileUtils.readFileToByteArray(chainFile);
      return BasicX509Utils.getPemObjects(new FileInputStream(chainFile)).stream()
        .filter(o -> o instanceof X509CertificateHolder)
        .map(o -> (X509CertificateHolder) o)
        .map(x509CertificateHolder -> x509CertificateHolder.getSubject().toString())
        .collect(Collectors.toList());
    }
    catch (Exception ex) {
      return null;
    }
  }

  private File getInstanceDir(String instance) {
    CAService caService = caServices.getCAService(instance);
    File instancesDir = new File(basicServiceConfig.getDataStoreLocation(), "instances");
    File instanceDir = new File(instancesDir, instance);
    return instanceDir;
  }

  private boolean getBoolean(Boolean booleanObject) {
    return booleanObject == null ? false : booleanObject;
  }

}
