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

package se.swedenconnect.ca.service.base.configuration.instance.mock;

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
import se.swedenconnect.ca.service.base.configuration.instance.ca.AbstractBasicCA;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

/**
 * This is a Mock test implementation of a Basic CA used in the MocRepoCAServices
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class MockCA extends AbstractBasicCA {

  public MockCA(PrivateKey privateKey, List<X509CertificateHolder> caCertificateChain,
    CARepository caRepository, CertificateIssuerModel certIssuerModel,
    CRLIssuerModel crlIssuerModel, List<String> crlDistributionPoints) throws NoSuchAlgorithmException {
    super(privateKey, caCertificateChain, caRepository, certIssuerModel, crlIssuerModel, crlDistributionPoints);
  }

  @Override protected DefaultCertificateModelBuilder getBaseCertificateModelBuilder(CertNameModel subject, PublicKey publicKey,
    X509CertificateHolder issuerCertificate, CertificateIssuerModel certificateIssuerModel) throws CertificateIssuanceException {
    DefaultCertificateModelBuilder certModelBuilder = DefaultCertificateModelBuilder.getInstance(publicKey, getCaCertificate(),
      certificateIssuerModel);
    certModelBuilder
      .subject(subject)
      .includeAki(true)
      .includeSki(true)
      .basicConstraints(new BasicConstraintsModel(false, false))
      .keyUsage(new KeyUsageModel(KeyUsage.digitalSignature))
      .crlDistributionPoints(crlDistributionPoints.isEmpty() ? null : crlDistributionPoints);

    if (ocspResponderUrl != null) {
      certModelBuilder.ocspServiceUrl(ocspResponderUrl);
    }

    return certModelBuilder;
  }
}
