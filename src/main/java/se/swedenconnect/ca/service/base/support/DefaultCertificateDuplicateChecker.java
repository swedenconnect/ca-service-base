package se.swedenconnect.ca.service.base.support;

import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;

/**
 * The default processor for handling equivalent certificates
 */
@Slf4j
public class DefaultCertificateDuplicateChecker extends AbstractCertificateDuplicateChecker {

  /** {@inheritDoc} */
  @Override protected X509Certificate getPreferredEquivalentCert(X509Certificate firstCertificate, X509Certificate otherCertificate) {

    // If both certs are identical, just return the first certificate
    if (firstCertificate.equals(otherCertificate)){
      if (log.isDebugEnabled()){
        log.trace("Identical certificates. Removing certificate duplicate for {}", otherCertificate.getSubjectX500Principal());
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
