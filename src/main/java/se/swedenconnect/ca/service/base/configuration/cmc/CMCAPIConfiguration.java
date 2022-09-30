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

package se.swedenconnect.ca.service.base.configuration.cmc;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.io.FileSystemResource;
import se.swedenconnect.ca.cmc.api.CMCCaApi;
import se.swedenconnect.ca.cmc.api.CMCRequestParser;
import se.swedenconnect.ca.cmc.api.CMCResponseFactory;
import se.swedenconnect.ca.cmc.auth.AuthorizedCmcOperation;
import se.swedenconnect.ca.cmc.auth.CMCValidator;
import se.swedenconnect.ca.cmc.auth.impl.DefaultCMCValidator;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry;
import se.swedenconnect.ca.service.base.ca.CAServices;
import se.swedenconnect.ca.service.base.configuration.audit.AuditCMCRequestParser;
import se.swedenconnect.ca.service.base.utils.GeneralCAUtils;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Bean Configuration for CMC API
 */
@Slf4j
@Configuration
public class CMCAPIConfiguration {

  /**
   * Bean providing a map of CMC API handlers for each CA instance
   *
   * @param caServices CA services
   * @param cmcConfigProperties CMC configuration properties
   * @param replayCheckerProvider replay check provider
   * @param cmcApiProvider CMC API provider
   * @return Map of CMC API handlers
   * @throws Exception error creating this bean
   */
  @Bean
  @DependsOn("BasicServiceConfig")
  Map<String, CMCCaApi> cmcCaApiMap(
    CAServices caServices,
    CMCConfigProperties cmcConfigProperties,
    CMCReplayCheckerProvider replayCheckerProvider,
    CMCApiProvider cmcApiProvider) throws Exception {

    Map<String, CMCCaApi> cmcCaApiMap = new HashMap<>();
    if (!cmcConfigProperties.isEnabled()) {
      log.info("CMC API disabled");
      return cmcCaApiMap;
    }
    final Map<String, CMCConfigProperties.CMCConfigData> cmcInstanceConfMap = cmcConfigProperties.getInstance();
    final List<String> caServiceKeys = caServices.getCAServiceKeys();
    for (String instanceKey : caServiceKeys) {

      CMCConfigProperties.CMCConfigData cmcConfigData = getConfigData(cmcInstanceConfMap, instanceKey);
      if (cmcConfigData == null) {
        continue;
      }
      log.info("Enabling CMC API for instance {}", instanceKey);

      // Collect data from config
      PkiCredential signerKey = getSignerKey(cmcConfigData);
      //X509CertificateHolder[] cmcClientCerts = getClientCerts(cmcConfigData.getTrustedClientCertsLocation());

      // Make CMC CA API
      final CAService caService = caServices.getCAService(instanceKey);
      //CMCValidator cmcValidator = new DefaultCMCValidator(cmcClientCerts);
      ContentSigner contentSigner = new JcaContentSignerBuilder(
        CAAlgorithmRegistry.getSigAlgoName(cmcConfigData.getAlgorithm())).build(
        signerKey.getPrivateKey());
      CMCRequestParser requestParser = new CMCRequestParser(getCMCValidator(instanceKey, cmcConfigProperties),
        replayCheckerProvider.getCMCReplayChecker(instanceKey));
      CMCResponseFactory responseFactory = new CMCResponseFactory(signerKey.getCertificateChain(), contentSigner);
      CMCCaApi cmcCaApi = cmcApiProvider.getCmcCaApi(instanceKey, caService, requestParser, responseFactory);
      cmcCaApiMap.put(instanceKey, cmcCaApi);
      if (log.isDebugEnabled()) {
        log.debug("CMC Response signer: {}", signerKey.getCertificate().getSubjectX500Principal());
        log.debug("CMC API implementation: {}", cmcCaApi.getClass());
        log.debug("CMC Signing algorithm: {}", cmcConfigData.getAlgorithm());
      }
    }
    return cmcCaApiMap;
  }

  /**
   * Creating bean with a map of CMC request parsers used specifically to support audit logging. The regular
   * request parser can't be used without violating its replay checker. For this reason, separate request parsers
   * without replay checking is provided by this bean to support the audit logger.
   *
   * @param caServices CA services
   * @param cmcConfigProperties CMC configuration properties
   * @return map of CMC request parsers without replay checker
   * @throws IOException error parsing data
   */
  @Bean
  Map<String, AuditCMCRequestParser> cmcRequestParserMap(CAServices caServices, CMCConfigProperties cmcConfigProperties)
    throws IOException {
    Map<String, AuditCMCRequestParser> requestParserMap = new HashMap<>();
    final List<String> caServiceKeys = caServices.getCAServiceKeys();
    for (String instanceKey : caServiceKeys) {
      AuditCMCRequestParser requestParser = new AuditCMCRequestParser(
        getCMCValidator(instanceKey, cmcConfigProperties));
      requestParserMap.put(instanceKey, requestParser);
    }
    return requestParserMap;
  }

  private CMCValidator getCMCValidator(String instanceKey, CMCConfigProperties cmcConfigProp) throws IOException {

    final List<CMCConfigProperties.ClientAuthorization> authorizationList = cmcConfigProp.getClient();
    List<X509CertificateHolder> clientCerts = new ArrayList<>();
    Map<X509CertificateHolder, List<AuthorizedCmcOperation>> authMap = new HashMap<>();
    if (authorizationList == null || authorizationList.isEmpty()) {
      // No authorized clients found
      return new DefaultCMCValidator(new X509CertificateHolder[0]);
    }
    for (CMCConfigProperties.ClientAuthorization clientAuthorization : authorizationList) {
      final X509CertificateHolder cert = getCertFromLocation(clientAuthorization.getCertLocation());
      final Map<String, List<AuthorizedCmcOperation>> instanceAuthzMap = clientAuthorization.getAuthorization();
      if (instanceAuthzMap.containsKey(instanceKey)) {
        // This client is authorized for this instance. Add authorizations
        clientCerts.add(cert);
        authMap.put(cert, instanceAuthzMap.get(instanceKey));
        if (log.isDebugEnabled()) {
          log.debug("Instance {} authorized CMC client: {} - with authorization rights: {}", instanceKey,
            cert.getSubject().toString(),
            String.join(", ", instanceAuthzMap.get(instanceKey)
              .stream()
              .map(AuthorizedCmcOperation::toString)
              .collect(Collectors.toList())));
        }
      }
    }
    DefaultCMCValidator cmcValidator = new DefaultCMCValidator(clientCerts.toArray(new X509CertificateHolder[0]));
    cmcValidator.setClientAuthorizationMap(authMap);
    return cmcValidator;
  }

  private CMCConfigProperties.CMCConfigData getConfigData(
    Map<String, CMCConfigProperties.CMCConfigData> cmcInstanceConfMap, String instanceKey) {

    CMCConfigProperties.CMCConfigData defaultConf = null;
    CMCConfigProperties.CMCConfigData instanceConf = null;

    if (cmcInstanceConfMap.containsKey("default")) {
      defaultConf = cmcInstanceConfMap.get("default");
    }
    if (cmcInstanceConfMap.containsKey(instanceKey)) {
      instanceConf = cmcInstanceConfMap.get(instanceKey);
    }

    if (defaultConf == null && instanceConf == null) {
      return null;
    }

    if (defaultConf == null) {
      return instanceConf;
    }
    if (instanceConf == null) {
      return defaultConf;
    }

    // Both instance and default config exists. Get a complete value set. Prefer set instance values and fill in with default values if instance value is null
    CMCConfigProperties.CMCConfigData conf = CMCConfigProperties.CMCConfigData.builder()
      .algorithm(cfgProp(instanceConf.getAlgorithm(), defaultConf.getAlgorithm()))
      .alias(cfgProp(instanceConf.getAlias(), defaultConf.getAlias()))
      .location(cfgProp(instanceConf.getLocation(), defaultConf.getLocation()))
      .password(cfgProp(instanceConf.getPassword(), defaultConf.getPassword()))
      .build();

    return conf;
  }

  private String cfgProp(String val, String def) {
    return val != null ? val : def;
  }

  private X509CertificateHolder getCertFromLocation(String certLocation) throws IOException {
    File location = GeneralCAUtils.locateFileOrResource(certLocation);
    final List<X509CertificateHolder> certsFromFile = GeneralCAUtils.getPEMCertsFromFile(location);
    if (certsFromFile.size() != 1) {
      throw new IllegalArgumentException("A single certificate file is required");
    }
    return certsFromFile.get(0);
  }

  private PkiCredential getSignerKey(CMCConfigProperties.CMCConfigData cmcConfigData)
    throws Exception {
    final File ksFile = GeneralCAUtils.locateFileOrResource(cmcConfigData.getLocation());
    final char[] password = cmcConfigData.getPassword().toCharArray();
    final String alias = cmcConfigData.getAlias();
    String type = ksFile.getName().toLowerCase().endsWith(".p12")
      ? "PKCS12"
      : "JKS";
    PkiCredential credential = new KeyStoreCredential(new FileSystemResource(ksFile), type, password, alias, password);
    credential.init();
    return credential;
  }
}
