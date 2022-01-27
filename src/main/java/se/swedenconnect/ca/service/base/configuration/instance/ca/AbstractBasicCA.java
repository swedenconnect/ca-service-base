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

package se.swedenconnect.ca.service.base.configuration.instance.ca;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.issuer.impl.AbstractCAService;
import se.swedenconnect.ca.engine.ca.issuer.impl.BasicCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuer;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.engine.revocation.crl.impl.DefaultCRLIssuer;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.List;

/**
 * Abstract basic implementation of a CA based on the core CA ca-engine module
 *
 * This forms a basic model for providing a complete CA that includes a CA repository,
 * a CRL issuer and optionally an OCSP responder.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractBasicCA extends AbstractCAService<DefaultCertificateModelBuilder> {

  @Getter protected CertificateIssuer certificateIssuer;
  protected CRLIssuer crlIssuer;
  @Setter protected OCSPResponder ocspResponder;
  @Setter protected X509CertificateHolder ocspCertificate;
  @Getter protected final List<String> crlDistributionPoints;
  @Setter @Getter protected String ocspResponderUrl;

  public AbstractBasicCA(PrivateKey privateKey, List<X509CertificateHolder> caCertificateChain, CARepository caRepository,
    CertificateIssuerModel certIssuerModel, CRLIssuerModel crlIssuerModel, List<String> crlDistributionPoints)
    throws NoSuchAlgorithmException {
    super(caCertificateChain, caRepository);
    this.certificateIssuer = new BasicCertificateIssuer(certIssuerModel, getCaCertificate().getSubject(), privateKey);
    if (crlIssuerModel != null) {
      this.crlIssuer = new DefaultCRLIssuer(crlIssuerModel, privateKey);
      // Make sure that at least one CRL is published
      if (getCurrentCrl() == null) {
        publishNewCrl();
      }
    }
    this.crlDistributionPoints = crlDistributionPoints;
  }

  @Override public CertificateIssuer getCertificateIssuer() {
    return certificateIssuer;
  }

  @Override protected CRLIssuer getCrlIssuer() {
    return crlIssuer;
  }

  @Override public OCSPResponder getOCSPResponder() {
    return ocspResponder;
  }

  @Override public X509CertificateHolder getOCSPResponderCertificate() {
    return ocspCertificate;
  }

  @Override public String getCaAlgorithm() {
    return certificateIssuer.getCertificateIssuerModel().getAlgorithm();
  }

  @Override public List<String> getCrlDpURLs() {
    return crlDistributionPoints;
  }

  @Override public String getOCSPResponderURL() {
    return ocspResponderUrl;
  }

}
