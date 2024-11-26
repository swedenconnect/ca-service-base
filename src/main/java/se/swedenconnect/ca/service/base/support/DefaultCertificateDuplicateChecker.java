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

import lombok.extern.slf4j.Slf4j;

/**
 * The default processor for handling equivalent certificates.
 */
@Slf4j
public class DefaultCertificateDuplicateChecker extends AbstractCertificateDuplicateChecker {

  /** {@inheritDoc} */
  @Override
  protected X509Certificate getPreferredEquivalentCert(final X509Certificate firstCertificate,
      final X509Certificate otherCertificate) {

    // If both certs are identical, just return the first certificate
    if (firstCertificate.equals(otherCertificate)) {
      if (log.isDebugEnabled()) {
        log.trace("Identical certificates. Removing certificate duplicate for {}",
            otherCertificate.getSubjectX500Principal());
      }
      return firstCertificate;
    }

    // Assume that the first certificate is the chosen one
    X509Certificate selectedCert = firstCertificate;
    X509Certificate droppedCert = otherCertificate;

    // Check if the other certificate is more recent
    if (firstCertificate.getNotBefore().before(otherCertificate.getNotBefore())) {
      // Yes, select the other certificate instead
      selectedCert = otherCertificate;
      droppedCert = firstCertificate;
    }

    // Log the result
    if (log.isTraceEnabled()) {
      log.trace("Keeping cert issued {} and removing cert issued {} for {}",
          selectedCert.getNotBefore(), droppedCert.getNotBefore(), selectedCert.getSubjectX500Principal());
    }
    return selectedCert;
  }
}
