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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.util.Date;

/**
 * Data at CA service audit events.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CAAuditEventData {

  /** CA instance */
  private String caInstance;
  /** The certificate being issued */
  private String issuedCertificate;
  /** Certificate serial number */
  private BigInteger certSerialNumber;
  /** Certificate subject */
  private String subject;
  /** Revocation time */
  private Date revocationTime;
  /** Revocation reason */
  private Integer reason;
  /** CRL number */
  private BigInteger crlNumber;
  /** Exception recorded at event */
  private Exception exception;

  /**
   * Event data for certificate request
   * @param caInstance CA instance
   * @param subject subject for the certificate request
   */
  public CAAuditEventData(String caInstance, String subject) {
    this.caInstance = caInstance;
    this.subject = subject;
  }

  /**
   * Event data for issued certificates
   * @param caInstance CA instance
   * @param issuedCertificate the base64 encoded issued certificate
   * @param certSerialNumber the certificate serial number
   * @param subject the subject name of the certificate
   */
  public CAAuditEventData(String caInstance, String issuedCertificate, BigInteger certSerialNumber, String subject) {
    this.caInstance = caInstance;
    this.issuedCertificate = issuedCertificate;
    this.certSerialNumber = certSerialNumber;
    this.subject = subject;
  }

  /**
   * Event data for certificate revocation
   * @param caInstance CA instance
   * @param certSerialNumber certificate serial number
   * @param revocationTime revocation time
   * @param reason revocation reason
   * @param subject The subject of the certificate
   */
  public CAAuditEventData(String caInstance, BigInteger certSerialNumber, Date revocationTime, Integer reason, String subject) {
    this.caInstance = caInstance;
    this.certSerialNumber = certSerialNumber;
    this.revocationTime = revocationTime;
    this.reason = reason;
    this.subject = subject;
  }

  /**
   * Event data for new CRL publication
   * @param caInstance CA instance identifier
   * @param crlNumber CRL number
   */
  public CAAuditEventData(String caInstance, BigInteger crlNumber) {
    this.caInstance = caInstance;
    this.crlNumber = crlNumber;
  }
}
