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

package se.swedenconnect.ca.service.base.configuration.audit;

import com.cloudbees.syslog.Facility;
import com.cloudbees.syslog.MessageFormat;
import com.cloudbees.syslog.Severity;
import com.cloudbees.syslog.SyslogMessage;
import com.cloudbees.syslog.sender.SyslogMessageSender;
import com.cloudbees.syslog.sender.TcpSyslogMessageSender;
import com.cloudbees.syslog.sender.UdpSyslogMessageSender;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.audit.AuditEvent;
import org.springframework.util.StringUtils;
import se.swedenconnect.ca.service.base.configuration.properties.SyslogConfigProperties;

import java.io.CharArrayWriter;
import java.io.IOException;
import java.util.Optional;

/**
 * Extended Syslog Message sender.
 * <p>
 * This class is setup based on the settings for a syslog host in syslog.properties
 * <p>
 * This syslog message sender has an extra message send function for logging an AuditEvent, with extra functionality
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

  public ExtSyslogMessageSender(SyslogConfigProperties.SyslogConfigData scd) {
    this.syslogConfigData = scd;

    clientHostName = System.getenv(HOSTNAME_ENV_LABEL);
    if (StringUtils.hasText(scd.getClienthostname())) {
      clientHostName = scd.getClienthostname();
    }

    try {
      loglevel = Severity.fromLabel(syslogConfigData.getLoglevel().toUpperCase());
    }
    catch (Exception ex) {
      try {
        loglevel = Severity.fromNumericalCode(Integer.parseInt(syslogConfigData.getLoglevel()));
      }
      catch (Exception ex2) {
        loglevel = Severity.fromNumericalCode(6);
      }
    }

    facility = Facility.fromNumericalCode(syslogConfigData.getFacility());
    checkSyslogConfig();

    MessageFormat messageFormat = MessageFormat.RFC_3164;
    switch (scd.getProtocol().toLowerCase()) {
    case "tcp":
    case "ssl":
      if (!scd.isBsd()) {
        messageFormat = MessageFormat.RFC_5425;
      }
      TcpSyslogMessageSender tcpMessageSender = new TcpSyslogMessageSender();
      tcpMessageSender.setDefaultMessageHostname(scd.getClienthostname());
      tcpMessageSender.setDefaultAppName(scd.getClientapp());
      tcpMessageSender.setDefaultFacility(facility);
      tcpMessageSender.setDefaultSeverity(Severity.fromNumericalCode(scd.getSeverity() != null ? scd.getSeverity() : DEFAULT_SEVERITY));
      tcpMessageSender.setSyslogServerHostname(scd.getHost());
      tcpMessageSender.setSyslogServerPort(scd.getPort());
      tcpMessageSender.setMessageFormat(messageFormat);

      if (scd.getProtocol().equalsIgnoreCase("ssl")) {
        tcpMessageSender.setSsl(true);
      }
      log.info("Configured TCP syslog export for audit logs on host {} port:{} ssl={}", scd.getHost(), scd.getPort(),
        scd.getProtocol().equalsIgnoreCase("ssl"));
      messageSender = tcpMessageSender;
      break;
    default:
      if (!scd.isBsd()) {
        messageFormat = MessageFormat.RFC_5424;
      }
      UdpSyslogMessageSender udpMessageSender = new UdpSyslogMessageSender();
      udpMessageSender.setDefaultMessageHostname(scd.getClienthostname());
      udpMessageSender.setDefaultAppName(scd.getClientapp());
      udpMessageSender.setDefaultFacility(facility);
      udpMessageSender.setDefaultSeverity(Severity.fromNumericalCode(DEFAULT_SEVERITY));
      udpMessageSender.setSyslogServerHostname(scd.getHost());
      udpMessageSender.setSyslogServerPort(scd.getPort());
      udpMessageSender.setMessageFormat(messageFormat);
      log.info("Configured UDP syslog export for audit logs on host {} port:{}", scd.getHost(), scd.getPort());
      messageSender = udpMessageSender;
    }
  }

  private void checkSyslogConfig() {
    if (!StringUtils.hasText(syslogConfigData.getHost())) {
      throw new IllegalArgumentException("Missing syslog host configuration");
    }
    if (syslogConfigData.getPort() < 1 || syslogConfigData.getPort() > 49151) {
      throw new IllegalArgumentException("Missing or illegal syslog port configuration");
    }
    switch (syslogConfigData.getProtocol()) {
    case "tcp":
    case "udp":
    case "ssl":
      break;
    default: {
      throw new IllegalArgumentException("Missing or illegal syslog protocol configuration");
    }
    }
    if (!StringUtils.hasText(clientHostName)) {
      throw new IllegalArgumentException("Missing syslog client host configuration. Set in syslog.properties or Env 'HOSTNAME'");
    }
    if (!StringUtils.hasText(syslogConfigData.getClientapp())) {
      throw new IllegalArgumentException("Missing syslog client app host configuration");
    }
    if (facility == null) {
      throw new IllegalArgumentException("Illegal syslog facility host configuration");
    }

  }

  /**
   * Method for sending an audit event to syslog.
   * <p>
   * This method classifies the severity of each event before sending it to syslog.
   * The event is logged if the severity is more critical than the set logging level.
   *
   * @param auditEvent The event to be logged
   * @throws IOException Catching errors caused by sending data to syslog
   */
  public void sendMessage(AuditEvent auditEvent) throws IOException {
    String type = auditEvent.getType();
    String jsonLogStr = objectMapper.writeValueAsString(auditEvent);
    Severity eventSeverity = getEventSeverity(type);

    // Check if the configured log level requires this event to be logged or suppressed
    if (eventSeverity.numericalCode() > loglevel.numericalCode()) {
      log.debug("Log event suppressed due to log level setting. Event: {}, Log-level: {}, Event-level: {}", type, loglevel.label(),
        eventSeverity.label());
      return;
    }

    SyslogMessage syslogMessage = (new SyslogMessage())
      .withAppName(this.syslogConfigData.getClientapp())
      .withFacility(this.facility)
      .withHostname(this.syslogConfigData.getHost())
      .withSeverity(eventSeverity)
      .withMsg(jsonLogStr);

    sendMessage(syslogMessage);
  }

  private Severity getEventSeverity(String type) {
    Optional<AuditEventEnum> eventEnumOptional = AuditEventEnum.getAuditEventFromTypeLabel(type);
    if (!eventEnumOptional.isPresent()) {
      return Severity.INFORMATIONAL;
    }

    //TODO Fix this list
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

  @Override
  public void sendMessage(CharArrayWriter charArrayWriter) throws IOException {
    messageSender.sendMessage(charArrayWriter);
  }

  @Override
  public void sendMessage(CharSequence charSequence) throws IOException {
    messageSender.sendMessage(charSequence);
  }

  @Override
  public void sendMessage(SyslogMessage syslogMessage) throws IOException {
    messageSender.sendMessage(syslogMessage);
  }

  @Override public void close() throws IOException {
    messageSender.close();
  }
}
