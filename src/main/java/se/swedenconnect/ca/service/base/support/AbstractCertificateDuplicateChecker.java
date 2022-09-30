package se.swedenconnect.ca.service.base.support;

import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * This generates a String identifier that needs to be the same before and after cross certification
 * This implementations use 2 parameters that are identical and unique before and after cross certification namely:
 *
 * <ul>
 *   <li>Subject name</li>
 *   <li>Subject public key</li>
 * </ul>
 *
 * <p>
 * The hash is set to SHA-1 by default because this ID has no security property beyond providing a unique identifier among trusted certificates
 * This identifier will be inserted manually in configuration files upon blocking and should be as short as possible while still being unique
 * For this purpose SHA-1 seems ideal.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractCertificateDuplicateChecker implements CertificateDuplicateChecker {

  /** The hash algorithm used to create data hashes for duplication checking */
  @Setter protected String hashAlgoId = "SHA-1";

  /** {@inheritDoc} */
  @Override
  public String getCertId(X509Certificate certificate) {
    try {
      if (certificate == null){
        return null;
      }
      MessageDigest digest = MessageDigest.getInstance(hashAlgoId);
      digest.update(certificate.getSubjectX500Principal().getEncoded());
      digest.update(certificate.getPublicKey().getEncoded());
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest());
    } catch (NoSuchAlgorithmException ex){
      // This function should never fail unless there is a generic setup error. Throw unchecked exception
      throw new RuntimeException(ex);
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> removeEquivalentCerts(List<X509Certificate> certificateList) {
    Map<String, X509Certificate> uniqueCertsMap = new HashMap<>();
    for (X509Certificate certificate : certificateList) {
      String certId = getCertId(certificate);
      // check for duplicate
      if (uniqueCertsMap.containsKey(certId)){
        X509Certificate preferredCertificate = getPreferredEquivalentCert(uniqueCertsMap.get(certId), certificate);
        uniqueCertsMap.put(certId, preferredCertificate);
      } else {
        uniqueCertsMap.put(certId, certificate);
      }
    }
    log.debug("Found {} duplicates", certificateList.size() - uniqueCertsMap.size());
    return uniqueCertsMap.keySet().stream().map(s -> uniqueCertsMap.get(s)).collect(Collectors.toList());
  }

  /**
   * Function that decides which certificate that is preferred out of 2 equivalent certificate with identical certID
   * @param firstCertificate the first equivalent certificate
   * @param otherCertificate the other equivalent certificate
   * @return the preferred equivalent certificate
   */
  protected abstract X509Certificate getPreferredEquivalentCert(X509Certificate firstCertificate, X509Certificate otherCertificate);
}
