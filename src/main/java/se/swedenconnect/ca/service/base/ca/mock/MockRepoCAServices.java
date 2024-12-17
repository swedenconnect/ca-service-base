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
package se.swedenconnect.ca.service.base.ca.mock;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.service.base.ca.impl.AbstractBasicCA;
import se.swedenconnect.ca.service.base.ca.impl.AbstractDefaultCAServices;
import se.swedenconnect.ca.service.base.configuration.BasicServiceConfig;
import se.swedenconnect.ca.service.base.configuration.instance.InstanceConfiguration;
import se.swedenconnect.ca.service.base.configuration.keys.PkiCredentialFactory;
import se.swedenconnect.ca.service.base.configuration.properties.CAConfigData;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * This is an implementation of the CA Services bean that use a mockup implementation of the CA repository purely based
 * on storing CA repository data in a local json file. This implementation is intended for test and evaluation purposes
 * only and SHOULD NOT be used in production.
 *
 * <p>
 * It is highly recommended for production environments to implement a CA repository based an a real database
 * implementation with appropriate management of backup and protection against conflicts and simultaneous storage and/or
 * revocation requests.
 * </p>
 */
public class MockRepoCAServices extends AbstractDefaultCAServices {

  /**
   * Constructor for a mock repo CA service.
   *
   * @param instanceConfiguration instance configuration
   * @param pkiCredentialFactory ca credentials
   * @param basicServiceConfig service configuration
   * @param caRepositoryMap map of CA repositories
   * @param applicationEventPublisher event publisher for audit logging
   */
  @Autowired
  public MockRepoCAServices(final InstanceConfiguration instanceConfiguration,
      final PkiCredentialFactory pkiCredentialFactory, final BasicServiceConfig basicServiceConfig,
      final Map<String, CARepository> caRepositoryMap, final ApplicationEventPublisher applicationEventPublisher) {
    super(instanceConfiguration, pkiCredentialFactory, basicServiceConfig, caRepositoryMap, applicationEventPublisher);
  }

  /** {@inheritDoc} */
  @Override
  protected AbstractBasicCA getBasicCaService(final String instance, final String type,
      final PkiCredential issuerCredential,
      final CARepository caRepository, final CertificateIssuerModel certIssuerModel,
      final CRLIssuerModel crlIssuerModel,
      final List<String> crlDistributionPoints)
      throws NoSuchAlgorithmException, IOException, CertificateEncodingException {
    // Returning the same Basic CA service for any instance;
    return new MockCA(issuerCredential, caRepository, certIssuerModel, crlIssuerModel, crlDistributionPoints);
  }

  /** {@inheritDoc} */
  @Override
  protected void customizeOcspCertificateModel(final DefaultCertificateModelBuilder certModelBuilder,
      final String instance) {
    // We don't add any custom content of OCSP service certificates
  }

  /** {@inheritDoc} */
  @Override
  protected X509CertificateHolder generateSelfIssuedCaCert(final PkiCredential caKeySource,
      final CAConfigData caConfigData,
      final String instance, final String baseUrl)
      throws NoSuchAlgorithmException, CertificateIssuanceException {
    // Use the default self issued certificate implementation provided by the abstract class
    return this.defaultGenerateSelfIssuedCaCert(caKeySource, caConfigData);
  }

}
