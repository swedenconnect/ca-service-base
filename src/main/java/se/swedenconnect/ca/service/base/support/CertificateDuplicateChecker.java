package se.swedenconnect.ca.service.base.support;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface for providing generic functions related to identification and sorting among equivalent certificates.
 *
 * Equivalent certificates are certificates issued to the same subject, for the same key, for the same purpose
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CertificateDuplicateChecker {

  /**
   * Function for providing a unique identifier of a certificate. This ID must be the same both before and after cross certification
   * under the policy root. Suitable parameters to use as input are subject name and subject key. Unsuitable parameters are issuer and
   * similar parameters that will change when the certificate is re-issued under a new issuer in the cross-certification process.
   *
   * @param certificate the certificate
   * @return
   */
  String getCertId(X509Certificate certificate);

  /**
   * This reduces a list of certificates and removes equivalent (re-issued) certificates issued to the same entity
   *
   *
   * @param trustedCertList
   * @return
   */
  List<X509Certificate> removeEquivalentCerts(List<X509Certificate> trustedCertList);

}
