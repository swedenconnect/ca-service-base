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

import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.util.StringUtils;

/**
 * This class provides audit event data for the audit log in the form of AuditApplicationEvent objects.
 */
public class AuditEventFactory {

  /** The default audit record principal */
  public static final String DEFAULT_AUDIT_PRINCIPAL = "CA Service";

  /** Date format for formatting Date to String */
  private final static SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

  /** Hide constructor */
  private AuditEventFactory() {
  }

  /**
   * Get audit event
   *
   * @param event event
   * @param message message
   * @return {@link AuditApplicationEvent}
   */
  public static AuditApplicationEvent getAuditEvent(final AuditEventEnum event, final String message) {
    return getAuditEvent(event, null, message);
  }

  /**
   * Create an Audit application event with event data
   *
   * @param event the type of event
   * @param eventData state information holding information about the event
   * @param message readable message about the event
   * @return Audit event object for the audit log system
   */
  public static AuditApplicationEvent getAuditEvent(final AuditEventEnum event, final CAAuditEventData eventData,
      final String message) {
    return getAuditEvent(event, eventData, message, DEFAULT_AUDIT_PRINCIPAL);
  }

  /**
   * Create an Audit application event with event data
   *
   * @param event the type of event
   * @param eventData state information holding information about the event
   * @param message readable message about the event
   * @param principal the principal responsible for the event
   * @return Audit event object for the audit log system
   */
  public static AuditApplicationEvent getAuditEvent(final AuditEventEnum event, final CAAuditEventData eventData,
      final String message, final String principal) {
    final Map<String, Object> data = new HashMap<>();

    addBasicSessionData(data, eventData, message);

    switch (event) {

    case certificateRequested:
      data.put("subject", eventData.getSubject());
      break;
    case selfSignedCACertIsssued:
    case ocspCertificateIssued:
    case certificateIssued:
      data.put("subject", eventData.getSubject());
      data.put("serialNumber", eventData.getCertSerialNumber().toString(16));
      data.put("certificate", eventData.getIssuedCertificate());
      break;
    case revocationRequested:
      data.put("serialNumber", eventData.getCertSerialNumber().toString(16));
      data.put("reason", eventData.getReason());
      break;
    case certificateRevoked:
      data.put("subject", eventData.getSubject());
      data.put("serialNumber", eventData.getCertSerialNumber().toString(16));
      data.put("revocationTime", DATE_FORMAT.format(eventData.getRevocationTime()));
      data.put("reason", eventData.getReason());
      break;
    case crlPublished:
      data.put("CRLnumber", eventData.getCrlNumber());
      break;
    case expiredCertDeleted:
      data.put("serialNumber", eventData.getCertSerialNumber().toString(16));
      break;
    default:
      break;
    }

    return new AuditApplicationEvent(principal, event.getEventName(), data);
  }

  private static void addBasicSessionData(final Map<String, Object> data, final CAAuditEventData eventData,
      final String message) {
    if (StringUtils.hasText(message)) {
      data.put("message", message);
    }

    if (eventData != null) {
      if (eventData.getCaInstance() != null) {
        data.put("instance", eventData.getCaInstance());
      }
      if (eventData.getException() != null) {
        data.put("exception", eventData.getException());
      }
    }
  }

}
