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

package se.swedenconnect.ca.service.base.configuration;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.boot.actuate.audit.AuditEventRepository;
import org.springframework.boot.actuate.audit.InMemoryAuditEventRepository;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.io.ResourceLoader;
import se.swedenconnect.ca.service.base.configuration.audit.CAServiceContextListener;
import se.swedenconnect.ca.service.base.configuration.audit.ExtSyslogMessageSender;
import se.swedenconnect.ca.service.base.configuration.keys.PkiCredentialFactory;

import javax.servlet.ServletContextListener;
import java.io.File;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Configuration class to provide constructed beans
 */
@Configuration
@Slf4j
@NoArgsConstructor
public class BeanConfig implements ApplicationEventPublisherAware {

  private ApplicationEventPublisher applicationEventPublisher;

  /**
   * Service listener bean
   *
   * @return {@link ServletListenerRegistrationBean}
   */
  @Bean
  ServletListenerRegistrationBean<ServletContextListener> serviceContextListener() {
    ServletListenerRegistrationBean<ServletContextListener> servletListenerRegistrationBean = new ServletListenerRegistrationBean<>();
    servletListenerRegistrationBean.setListener(new CAServiceContextListener(applicationEventPublisher));
    return servletListenerRegistrationBean;
  }

  /**
   * Basic service configuration
   *
   * @param configLocation configuration data location
   * @param serviceBaseUrl service base URL
   * @param serviceContextPath context path of the service
   * @return basic service configuration
   */
  @Bean (name = "BasicServiceConfig")
  BasicServiceConfig basicServiceConfig(
    @Value("${ca-service.config.data-directory}") String configLocation,
    @Value("${ca-service.config.base-url}") String serviceBaseUrl,
    @Value("${server.servlet.context-path:#{null}}") String serviceContextPath
  ) {
    Security.insertProviderAt(new BouncyCastleProvider(),1);
    log.info("Available crypto providers: {}", Arrays.stream(Security.getProviders())
      .map(Provider::getName)
      .collect(Collectors.joining(",")));
    final Provider bcProvider = Security.getProvider("BC");
    log.info("Bouncycastle version: {}", bcProvider.getVersionStr());
    log.info("JRE Path: {}", System.getProperty("java.home"));

    BasicServiceConfig basicServiceConfig = new BasicServiceConfig();
    if (StringUtils.isNotBlank(configLocation)) {
      basicServiceConfig.setDataStoreLocation(new File(
        configLocation.endsWith("/")
          ? configLocation.substring(0, configLocation.length() - 1)
          : configLocation
      ));
    }
    else {
      basicServiceConfig.setDataStoreLocation(new File(System.getProperty("user.dir"), "target/temp/ca-config"));
      if (!basicServiceConfig.getDataStoreLocation().exists()) {
        basicServiceConfig.getDataStoreLocation().mkdirs();
      }
    }
    basicServiceConfig.setServiceUrl(serviceContextPath == null
      ? serviceBaseUrl
      : serviceBaseUrl + serviceContextPath);
    basicServiceConfig.setServiceHostUrl(serviceBaseUrl);
    return basicServiceConfig;
  }

  /**
   * Create the PKI Credential factory
   *
   * @param hsmExternalCfgLocations the locations of external PKCS11 configuration files
   * @return {@link PkiCredentialFactory}
   */
  @Bean
  PkiCredentialFactory pkiCredentialFactory(
    @Value("${ca-service.pkcs11.external-config-locations:#{null}}") List<String> hsmExternalCfgLocations) {

    if (hsmExternalCfgLocations != null && hsmExternalCfgLocations.size() != 1){
      throw new RuntimeException("Only one PKCS11 config file is allowed");
    }

    PkiCredentialFactory pkiCredentialFactory = new PkiCredentialFactory(
      hsmExternalCfgLocations == null ? null : hsmExternalCfgLocations.get(0));
    pkiCredentialFactory.setMockKeyLen(3072);
    return pkiCredentialFactory;
  }

  /**
   * Provide an {@link AuditEventRepository} for audit logging
   *
   * @param syslogMessageSenderList the list of syslog message senders
   * @return {@link AuditEventRepository}
   * @throws Exception error instantiating the bean
   */
  @Bean
  @DependsOn("syslogMessageSender")
  AuditEventRepository auditEventRepository(List<ExtSyslogMessageSender> syslogMessageSenderList) throws Exception {
    if (syslogMessageSenderList.isEmpty()) {
      return new InMemoryAuditEventRepository();
    }

    return new AuditEventRepository() {
      Logger log = LoggerFactory.getLogger(AuditEventRepository.class);

      @Override
      public void add(AuditEvent auditEvent) {
        syslogMessageSenderList.stream().forEach(syslogMessageSender -> {
          try {
            syslogMessageSender.sendMessage(auditEvent);
          }
          catch (IOException e) {
            log.error("failed to send audit log to syslog {}", auditEvent.toString());
            e.printStackTrace();
          }
        });
      }

      @Override
      public List<AuditEvent> find(String principal, Instant after, String type) {
        return new ArrayList<>();
      }
    };

  }

  /** {@inheritDoc} */
  @Override public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
    this.applicationEventPublisher = applicationEventPublisher;
  }

  /**
   * Creates a logo map bean based on logotype configuration
   *
   * @param resourceLoader image resource loader
   * @param logoLocation service logo location
   * @param iconLocation service icon location
   * @return logotype data map
   * @throws Exception error parsing data
   */
  @Bean
  Map<String, EmbeddedLogo> logoMap(
    ResourceLoader resourceLoader,
    @Value("${ca-service.config.logo:#{null}}")String logoLocation,
    @Value("${ca-service.config.icon:#{null}}")String iconLocation
  ) throws Exception {
    Map<String, EmbeddedLogo> logoMap = new HashMap<>();
    if (StringUtils.isNotBlank(logoLocation)) {
      logoMap.put("logo", new EmbeddedLogo(logoLocation, resourceLoader));
    }
    if (StringUtils.isNotBlank(iconLocation)) {
      logoMap.put("icon", new EmbeddedLogo(iconLocation, resourceLoader));
    }
    return logoMap;
  }
}
