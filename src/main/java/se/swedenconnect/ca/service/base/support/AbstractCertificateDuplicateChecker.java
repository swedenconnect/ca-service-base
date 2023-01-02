/*
 * Copyright 2023 Sweden Connect
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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

/**
 * This generates a String identifier that needs to be the same before and after cross certification.
 * <p>
 * This implementation use 2 parameters that are identical and unique before and after cross certification namely:
 * </p>
 *
 * <ul>
 * <li>Subject name</li>
 * <li>Subject public key</li>
 * </ul>
 *
 * <p>
 * The hash is set to SHA-1 by default because this ID has no security property beyond providing a unique identifier
 * among trusted certificates This identifier will be inserted manually in configuration files upon blocking and should
 * be as short as possible while still being unique For this purpose SHA-1 seems ideal.
 * </p>
 */
@Slf4j
public abstract class AbstractCertificateDuplicateChecker implements CertificateDuplicateChecker {

  /** The hash algorithm used to create data hashes for duplication checking */
  @Setter
  protected String hashAlgoId = "SHA-1";

  /** {@inheritDoc} */
  @Override
  public String getCertId(final X509Certificate certificate) {
    try {
      if (certificate == null) {
        return null;
      }
      final MessageDigest digest = MessageDigest.getInstance(this.hashAlgoId);
      digest.update(certificate.getSubjectX500Principal().getEncoded());
      digest.update(certificate.getPublicKey().getEncoded());
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest());
    }
    catch (final NoSuchAlgorithmException ex) {
      // This function should never fail unless there is a generic setup error. Throw unchecked exception
      throw new RuntimeException(ex);
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> removeEquivalentCerts(final List<X509Certificate> certificateList) {
    final Map<String, X509Certificate> uniqueCertsMap = new HashMap<>();
    for (final X509Certificate certificate : certificateList) {
      final String certId = this.getCertId(certificate);
      // check for duplicate
      if (uniqueCertsMap.containsKey(certId)) {
        final X509Certificate preferredCertificate =
            this.getPreferredEquivalentCert(uniqueCertsMap.get(certId), certificate);
        uniqueCertsMap.put(certId, preferredCertificate);
      }
      else {
        uniqueCertsMap.put(certId, certificate);
      }
    }
    log.debug("Found {} duplicates", certificateList.size() - uniqueCertsMap.size());
    return uniqueCertsMap.keySet().stream().map(s -> uniqueCertsMap.get(s)).collect(Collectors.toList());
  }

  /**
   * Function that decides which certificate that is preferred out of 2 equivalent certificate with identical certID
   *
   * @param firstCertificate the first equivalent certificate
   * @param otherCertificate the other equivalent certificate
   * @return the preferred equivalent certificate
   */
  protected abstract X509Certificate getPreferredEquivalentCert(X509Certificate firstCertificate,
      X509Certificate otherCertificate);
}
