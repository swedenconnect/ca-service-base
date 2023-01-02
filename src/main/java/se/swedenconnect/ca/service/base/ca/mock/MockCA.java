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
package se.swedenconnect.ca.service.base.ca.mock;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.util.List;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.service.base.ca.impl.AbstractBasicCA;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * This is a Mock test implementation of a Basic CA used in the MocRepoCAServices.
 */
public class MockCA extends AbstractBasicCA {

  /**
   * Constructor for Mock CA.
   *
   * @param issuerCredential issuer credentials
   * @param caRepository CA repository
   * @param certIssuerModel certificate issuer model
   * @param crlIssuerModel CRL issuer model
   * @param crlDistributionPoints CRL distribution points
   * @throws NoSuchAlgorithmException algorithm is not supported
   * @throws IOException generic data parsing errors
   * @throws CertificateEncodingException certificate encoding errors
   */
  public MockCA(final PkiCredential issuerCredential,
      final CARepository caRepository, final CertificateIssuerModel certIssuerModel,
      final CRLIssuerModel crlIssuerModel, final List<String> crlDistributionPoints)
      throws NoSuchAlgorithmException, IOException, CertificateEncodingException {
    super(issuerCredential, caRepository, certIssuerModel, crlIssuerModel, crlDistributionPoints);
  }

  /** {@inheritDoc} */
  @Override
  protected DefaultCertificateModelBuilder getBaseCertificateModelBuilder(final CertNameModel<?> subject,
      final PublicKey publicKey, final X509CertificateHolder issuerCertificate,
      final CertificateIssuerModel certificateIssuerModel) throws CertificateIssuanceException {
    final DefaultCertificateModelBuilder certModelBuilder =
        DefaultCertificateModelBuilder.getInstance(publicKey, this.getCaCertificate(),
            certificateIssuerModel);
    certModelBuilder
        .subject(subject)
        .includeAki(true)
        .includeSki(true)
        .basicConstraints(new BasicConstraintsModel(false, false))
        .keyUsage(new KeyUsageModel(KeyUsage.digitalSignature))
        .crlDistributionPoints(this.crlDistributionPoints.isEmpty() ? null : this.crlDistributionPoints);

    if (this.ocspResponderUrl != null) {
      certModelBuilder.ocspServiceUrl(this.ocspResponderUrl);
    }

    return certModelBuilder;
  }
}
