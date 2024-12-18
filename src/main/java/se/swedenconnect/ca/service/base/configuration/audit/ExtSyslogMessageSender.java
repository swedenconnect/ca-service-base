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
package se.swedenconnect.ca.service.base.configuration.audit;

import java.io.CharArrayWriter;
import java.io.IOException;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.util.StringUtils;

import com.cloudbees.syslog.Facility;
import com.cloudbees.syslog.MessageFormat;
import com.cloudbees.syslog.Severity;
import com.cloudbees.syslog.SyslogMessage;
import com.cloudbees.syslog.sender.SyslogMessageSender;
import com.cloudbees.syslog.sender.TcpSyslogMessageSender;
import com.cloudbees.syslog.sender.UdpSyslogMessageSender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import se.swedenconnect.ca.service.base.configuration.properties.SyslogConfigProperties;

/**
 * Extended Syslog Message sender.
 * <p>
 * This class is setup based on the settings for a syslog host in syslog.properties.
 * <p>
 * This syslog message sender has an extra message send function for logging an AuditEvent, with extra functionality.
 */
public class ExtSyslogMessageSender implements SyslogMessageSender {

  private static final Logger log = LoggerFactory.getLogger(SyslogConfig.class);
  private static final int DEFAULT_SEVERITY = 5;
  private static final String HOSTNAME_ENV_LABEL = "HOSTNAME";
  private static final ObjectMapper objectMapper = new ObjectMapper();
  private final SyslogConfigProperties.SyslogConfigData syslogConfigData;
  private final SyslogMessageSender messageSender;
  private String clientHostName;
  private Severity loglevel;
  private final Facility facility;

  /**
   * Constructor for syslog message sender setting up the connection to the syslog server.
   *
   * @param syslogConfigData syslog configuration data
   */
  public ExtSyslogMessageSender(final SyslogConfigProperties.SyslogConfigData syslogConfigData) {
    this.syslogConfigData = syslogConfigData;
    objectMapper.registerModule(new JavaTimeModule());

    this.clientHostName = System.getenv(HOSTNAME_ENV_LABEL);
    if (StringUtils.hasText(syslogConfigData.getClienthostname())) {
      this.clientHostName = syslogConfigData.getClienthostname();
    }

    try {
      this.loglevel = Severity.fromLabel(this.syslogConfigData.getLoglevel().toUpperCase());
    }
    catch (final Exception ex) {
      try {
        this.loglevel = Severity.fromNumericalCode(Integer.parseInt(this.syslogConfigData.getLoglevel()));
      }
      catch (final Exception ex2) {
        this.loglevel = Severity.fromNumericalCode(6);
      }
    }

    this.facility = Facility.fromNumericalCode(this.syslogConfigData.getFacility());
    this.checkSyslogConfig();

    MessageFormat messageFormat = MessageFormat.RFC_3164;
    switch (syslogConfigData.getProtocol().toLowerCase()) {
    case "tcp":
    case "ssl":
      if (!syslogConfigData.isBsd()) {
        messageFormat = MessageFormat.RFC_5425;
      }
      final TcpSyslogMessageSender tcpMessageSender = new TcpSyslogMessageSender();
      tcpMessageSender.setDefaultMessageHostname(syslogConfigData.getClienthostname());
      tcpMessageSender.setDefaultAppName(syslogConfigData.getClientapp());
      tcpMessageSender.setDefaultFacility(this.facility);
      tcpMessageSender.setDefaultSeverity(Severity.fromNumericalCode(
          syslogConfigData.getSeverity() != null ? syslogConfigData.getSeverity() : DEFAULT_SEVERITY));
      tcpMessageSender.setSyslogServerHostname(syslogConfigData.getHost());
      tcpMessageSender.setSyslogServerPort(syslogConfigData.getPort());
      tcpMessageSender.setMessageFormat(messageFormat);

      if (syslogConfigData.getProtocol().equalsIgnoreCase("ssl")) {
        tcpMessageSender.setSsl(true);
      }
      log.info("Configured TCP syslog export for audit logs on host {} port:{} ssl={}", syslogConfigData.getHost(),
          syslogConfigData.getPort(),
          syslogConfigData.getProtocol().equalsIgnoreCase("ssl"));
      this.messageSender = tcpMessageSender;
      break;
    default:
      if (!syslogConfigData.isBsd()) {
        messageFormat = MessageFormat.RFC_5424;
      }
      final UdpSyslogMessageSender udpMessageSender = new UdpSyslogMessageSender();
      udpMessageSender.setDefaultMessageHostname(syslogConfigData.getClienthostname());
      udpMessageSender.setDefaultAppName(syslogConfigData.getClientapp());
      udpMessageSender.setDefaultFacility(this.facility);
      udpMessageSender.setDefaultSeverity(Severity.fromNumericalCode(DEFAULT_SEVERITY));
      udpMessageSender.setSyslogServerHostname(syslogConfigData.getHost());
      udpMessageSender.setSyslogServerPort(syslogConfigData.getPort());
      udpMessageSender.setMessageFormat(messageFormat);
      log.info("Configured UDP syslog export for audit logs on host {} port:{}", syslogConfigData.getHost(),
          syslogConfigData.getPort());
      this.messageSender = udpMessageSender;
    }
  }

  private void checkSyslogConfig() {
    if (!StringUtils.hasText(this.syslogConfigData.getHost())) {
      throw new IllegalArgumentException("Missing syslog host configuration");
    }
    if (this.syslogConfigData.getPort() < 1 || this.syslogConfigData.getPort() > 49151) {
      throw new IllegalArgumentException("Missing or illegal syslog port configuration");
    }
    switch (this.syslogConfigData.getProtocol()) {
    case "tcp":
    case "udp":
    case "ssl":
      break;
    default: {
      throw new IllegalArgumentException("Missing or illegal syslog protocol configuration");
    }
    }
    if (!StringUtils.hasText(this.clientHostName)) {
      throw new IllegalArgumentException(
          "Missing syslog client host configuration. Set in syslog.properties or Env 'HOSTNAME'");
    }
    if (!StringUtils.hasText(this.syslogConfigData.getClientapp())) {
      throw new IllegalArgumentException("Missing syslog client app host configuration");
    }
    if (this.facility == null) {
      throw new IllegalArgumentException("Illegal syslog facility host configuration");
    }

  }

  /**
   * Method for sending an audit event to syslog.
   * <p>
   * This method classifies the severity of each event before sending it to syslog. The event is logged if the severity
   * is more critical than the set logging level.
   *
   * @param auditEvent The event to be logged
   * @throws IOException Catching errors caused by sending data to syslog
   */
  public void sendMessage(final AuditEvent auditEvent) throws IOException {
    final String type = auditEvent.getType();
    final String jsonLogStr = objectMapper.writeValueAsString(auditEvent);
    final Severity eventSeverity = this.getEventSeverity(type);

    // Check if the configured log level requires this event to be logged or suppressed
    if (eventSeverity.numericalCode() > this.loglevel.numericalCode()) {
      log.debug("Log event suppressed due to log level setting. Event: {}, Log-level: {}, Event-level: {}", type,
          this.loglevel.label(),
          eventSeverity.label());
      return;
    }

    final SyslogMessage syslogMessage = new SyslogMessage()
        .withAppName(this.syslogConfigData.getClientapp())
        .withFacility(this.facility)
        .withHostname(this.syslogConfigData.getHost())
        .withSeverity(eventSeverity)
        .withMsg(jsonLogStr);

    this.sendMessage(syslogMessage);
  }

  private Severity getEventSeverity(final String type) {
    final Optional<AuditEventEnum> eventEnumOptional = AuditEventEnum.getAuditEventFromTypeLabel(type);
    if (!eventEnumOptional.isPresent()) {
      return Severity.INFORMATIONAL;
    }

    // TODO Fix this list
    switch (eventEnumOptional.get()) {

    case startup:
    case shutdown:
    case certificateRequested:
    case revocationRequested:
    case crlPublished:
      return Severity.INFORMATIONAL;
    case selfSignedCACertIsssued:
    case certificateIssued:
    case ocspCertificateIssued:
      return Severity.NOTICE;
    case certificateRevoked:
      return Severity.WARNING;
    case internalError:
      return Severity.CRITICAL;
    default:
      return Severity.ERROR;
    }
  }

  /** {@inheritDoc} */
  @Override
  public void sendMessage(final CharArrayWriter charArrayWriter) throws IOException {
    this.messageSender.sendMessage(charArrayWriter);
  }

  /** {@inheritDoc} */
  @Override
  public void sendMessage(final CharSequence charSequence) throws IOException {
    this.messageSender.sendMessage(charSequence);
  }

  /** {@inheritDoc} */
  @Override
  public void sendMessage(final SyslogMessage syslogMessage) throws IOException {
    this.messageSender.sendMessage(syslogMessage);
  }

  /** {@inheritDoc} */
  @Override
  public void close() throws IOException {
    this.messageSender.close();
  }
}
