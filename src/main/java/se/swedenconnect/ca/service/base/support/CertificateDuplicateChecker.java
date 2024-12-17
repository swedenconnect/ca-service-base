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
package se.swedenconnect.ca.service.base.support;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface for providing generic functions related to identification and sorting among equivalent certificates.
 *
 * Equivalent certificates are certificates issued to the same subject, for the same key, for the same purpose.
 */
public interface CertificateDuplicateChecker {

  /**
   * Function for providing a unique identifier of a certificate. This ID must be the same both before and after cross
   * certification under the policy root. Suitable parameters to use as input are subject name and subject key.
   * Unsuitable parameters are issuer and similar parameters that will change when the certificate is re-issued under a
   * new issuer in the cross-certification process.
   *
   * @param certificate the certificate
   * @return certificate identifier that is unique among different certificates, but identical for certificates issued
   *           to the same subject using the same public key
   */
  String getCertId(final X509Certificate certificate);

  /**
   * This reduces a list of certificates and removes equivalent (re-issued) certificates issued to the same entity
   *
   * @param certificateList list of certificates to filter
   * @return list of the latest unique certificates issued found in the provided list of certificates
   */
  List<X509Certificate> removeEquivalentCerts(final List<X509Certificate> certificateList);

}
