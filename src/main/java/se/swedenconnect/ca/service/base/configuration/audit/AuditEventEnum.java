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

import java.util.Arrays;
import java.util.Optional;

/**
 * Audit events
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public enum AuditEventEnum {
    certificateRequested ("CERTIFICATE_REQUESTED"),
    revocationRequested ("REVOCATION_REQUESTED"),
    certificateIssued ("CERTIFICATE_ISSUED"),
    expiredCertDeleted("EXPIRED_CERT_DELETED"),
    certificateRevoked("CERTIFICATE_REVOKED"),
    ocspCertificateIssued("OCSP_CERT_ISSUED"),
    selfSignedCACertIsssued("SELF_SIGNED_CA_CERT_ISSUED"),
    crlPublished("CRL_PUBLISHED"),
    startup("CA_SERVICE_STARTUP"),
    shutdown("CA_SERVICE_SHUTDOWN"),
    internalError("INTERNAL_SERVER_ERROR");

    String eventName;

    AuditEventEnum(String eventName) {
        this.eventName = eventName;
    }

    public String getEventName() {
        return eventName;
    }

    public static Optional<AuditEventEnum> getAuditEventFromTypeLabel(String eventTypeLabel){
        return Arrays.stream(values())
                .filter(auditEvent -> auditEvent.getEventName().equalsIgnoreCase(eventTypeLabel))
                .findFirst();
    }
}
