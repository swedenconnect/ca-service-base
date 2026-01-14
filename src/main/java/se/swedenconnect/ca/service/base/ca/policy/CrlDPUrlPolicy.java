/*
 * Copyright 2026 Sweden Connect
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

package se.swedenconnect.ca.service.base.ca.policy;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModelPolicy;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.service.base.configuration.properties.CAConfigData;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CrlDPUrlPolicy implements CertificateModelPolicy {

  private final CAConfigData caConfigData;
  private final CAService caService;

  public CrlDPUrlPolicy(final CAConfigData caConfigData, final CAService caService) {
    this.caConfigData = caConfigData;
    this.caService = caService;
  }

  @Override
  public void applyPolicy(final CertificateModel certificateModel) throws CertificateIssuanceException {
    final List<String> crlDpURLs = caService.getCrlDpURLs();
    List<String> certModelDpURLs = new ArrayList<>();
    final List<ExtensionModel> extensionModels = certificateModel.getExtensionModels();
    for (final ExtensionModel extensionModel : extensionModels) {
      final List<Extension> extensions = extensionModel.getExtensions();
      for (Extension exception : extensions) {
        if (exception.getExtnId().equals(Extension.cRLDistributionPoints)) {
          if (crlDpURLs == null || crlDpURLs.isEmpty()) {
            throw new CertificateIssuanceException("CRL DP is included in request but no CRL DP URLs is provided by CA");
          }
          final CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(exception.getParsedValue());
          final DistributionPoint[] distributionPoints = crlDistPoint.getDistributionPoints();
          for (final DistributionPoint distributionPoint : distributionPoints) {
            final DistributionPointName dpName = distributionPoint.getDistributionPoint();
            final GeneralNames generalNames = GeneralNames.getInstance(dpName.getName());
            final GeneralName crlDpGeneralName = Arrays.stream(generalNames.getNames())
                .filter(name -> name.getTagNo() == 6)
                .findFirst()
                .orElseThrow(() -> new CertificateIssuanceException("No CDP URL in distribution point"));
            final String crlDp = ASN1IA5String.getInstance(crlDpGeneralName.getName()).getString();
            certModelDpURLs.add(crlDp);
          }
        }
      }
    }
    for (final String certModelDpUrl : certModelDpURLs) {
      if (!crlDpURLs.contains(certModelDpUrl)) {
        throw new CertificateIssuanceException(String.format("Invalid crl dp url: %s is not supported by CA [%s] " , certModelDpUrl, String.join(",", crlDpURLs)));
      }
    }
  }
}
