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

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModelPolicy;
import se.swedenconnect.ca.engine.ca.models.cert.extension.ExtensionModel;
import se.swedenconnect.ca.service.base.configuration.properties.CAConfigData;

import java.util.List;

public class OCSPLocationPolicy implements CertificateModelPolicy {
  private final CAConfigData caConfigData;
  private final CAService caService;

  public OCSPLocationPolicy(final CAConfigData caConfigData, final CAService caService) {
    this.caConfigData = caConfigData;
    this.caService = caService;
  }

  @Override
  public void applyPolicy(final CertificateModel certificateModel) throws CertificateIssuanceException {

    final String ocspLocation = caService.getOCSPResponderURL();
    final List<ExtensionModel> extensionModels = certificateModel.getExtensionModels();
    for (final ExtensionModel extensionModel : extensionModels) {
      final List<Extension> extensions = extensionModel.getExtensions();
      for (final Extension extension : extensions) {
        if (extension.getExtnId().equals(Extension.authorityInfoAccess)) {
          AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(extension.getParsedValue());
          final AccessDescription[] accessDescriptions = aia.getAccessDescriptions();
          for (final AccessDescription accessDescription : accessDescriptions) {
            if (accessDescription.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
              if (ocspLocation == null) {
                throw new CertificateIssuanceException(
                    "This CA has no OCSP responder, but Certificate model still advertises OCSP responder service");
              }
              final GeneralName accessLocation = accessDescription.getAccessLocation();
              final int tagNo = accessLocation.getTagNo();
              if (tagNo != GeneralName.uniformResourceIdentifier) {
                throw new CertificateIssuanceException("Illegal OCSP location tag no: " + tagNo);
              }
              final String extOCSPLocation = ASN1IA5String.getInstance(accessLocation.getName()).getString();
              if (!ocspLocation.equals(extOCSPLocation)) {
                throw new CertificateIssuanceException(
                    "OCSP location in request does not match CA OCSP location: " + ocspLocation);
              }
            }
          }
        }
      }
    }
  }
}
