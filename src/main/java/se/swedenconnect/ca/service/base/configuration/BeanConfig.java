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

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.service.base.configuration.audit.CAServiceContextListener;
import se.swedenconnect.ca.service.base.configuration.audit.ExtSyslogMessageSender;
import se.swedenconnect.ca.service.base.configuration.instance.InstanceConfiguration;
import se.swedenconnect.ca.service.base.configuration.instance.LocalJsonCARepository;
import se.swedenconnect.ca.service.base.configuration.properties.CAConfigData;

import javax.servlet.ServletContextListener;
import java.io.File;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Configuration class to provide constructed beans
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Configuration
@Slf4j
public class BeanConfig implements ApplicationEventPublisherAware {

  private ApplicationEventPublisher applicationEventPublisher;
  private final List<ExtSyslogMessageSender> syslogMessageSenderList;

  @Autowired
  public BeanConfig(List<ExtSyslogMessageSender> syslogMessageSenderList) {
    this.syslogMessageSenderList = syslogMessageSenderList;
  }

  @Bean
  ServletListenerRegistrationBean<ServletContextListener> proxyServiceContextListener() {
    ServletListenerRegistrationBean<ServletContextListener> servletListenerRegistrationBean = new ServletListenerRegistrationBean<>();
    servletListenerRegistrationBean.setListener(new CAServiceContextListener(applicationEventPublisher));
    return servletListenerRegistrationBean;
  }

  @Bean (name = "BasicServiceConfig")
  BasicServiceConfig basicServiceConfig(
    @Value("${ca-service.config.data-directory}") String configLocation,
    @Value("${ca-service.config.base-url}") String serviceBaseUrl,
    @Value("${server.servlet.context-path:#{null}}") String serviceContextPath
  ) {
    Security.insertProviderAt(new BouncyCastleProvider(),1);
    log.info("Available crypto providers: {}", String.join(",", Arrays.stream(Security.getProviders())
      .map(Provider::getName)
      .collect(Collectors.toList())));
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

  @Bean
  @DependsOn("syslogMessageSender")
  AuditEventRepository auditEventRepository() throws Exception {
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

  @Override public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
    this.applicationEventPublisher = applicationEventPublisher;
  }

  @Bean
  Map<String, EmbeddedLogo> logoMap(
    ResourceLoader resourceLoader,
    @Value("${ca-service.config.logo}")String logoLocation,
    @Value("${ca-service.config.icon}")String iconLocation
  ) throws Exception {
    Map<String, EmbeddedLogo> logoMap = new HashMap<>();
    logoMap.put("logo", new EmbeddedLogo(logoLocation, resourceLoader));
    logoMap.put("icon", new EmbeddedLogo(iconLocation, resourceLoader));
    return logoMap;
  }

}
