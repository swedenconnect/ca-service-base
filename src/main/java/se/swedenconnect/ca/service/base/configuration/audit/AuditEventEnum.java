/*
 * Copyright 2021-2022 Sweden Connect
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

import java.util.Arrays;
import java.util.Optional;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Audit events.
 */
@AllArgsConstructor
@Getter
public enum AuditEventEnum {
  /** Certificate requested */
  certificateRequested("CERTIFICATE_REQUESTED"),

  /** Revocation requested */
  revocationRequested("REVOCATION_REQUESTED"),

  /** Certificate issued */
  certificateIssued("CERTIFICATE_ISSUED"),

  /** Expired certificate deleted */
  expiredCertDeleted("EXPIRED_CERT_DELETED"),

  /** Certificate revoked */
  certificateRevoked("CERTIFICATE_REVOKED"),

  /** OCSP certificate issued */
  ocspCertificateIssued("OCSP_CERT_ISSUED"),

  /** Self signed CA certificate issued */
  selfSignedCACertIsssued("SELF_SIGNED_CA_CERT_ISSUED"),

  /** CRL Published */
  crlPublished("CRL_PUBLISHED"),

  /** Service startup */
  startup("CA_SERVICE_STARTUP"),

  /** Service shut down */
  shutdown("CA_SERVICE_SHUTDOWN"),

  /** Service internal error */
  internalError("INTERNAL_SERVER_ERROR");

  /** Event name */
  private String eventName;

  /**
   * Get audit event from label name
   *
   * @param eventTypeLabel event type label
   * @return Optional audit event type
   */
  public static Optional<AuditEventEnum> getAuditEventFromTypeLabel(final String eventTypeLabel) {
    return Arrays.stream(values())
        .filter(auditEvent -> auditEvent.getEventName().equalsIgnoreCase(eventTypeLabel))
        .findFirst();
  }
}
