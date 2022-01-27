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

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.service.base.configuration.BasicServiceConfig;
import se.swedenconnect.ca.service.base.configuration.instance.InstanceConfiguration;
import se.swedenconnect.ca.service.base.configuration.instance.ca.AbstractBasicCA;
import se.swedenconnect.ca.service.base.configuration.instance.impl.AbstractDefaultCAServices;
import se.swedenconnect.ca.service.base.configuration.keys.LocalKeySource;
import se.swedenconnect.ca.service.base.configuration.properties.CAConfigData;
import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;

/**
 * This is an implementation of of the CA Services bean that use a mockup
 * implementation of the CA repository purely based on storing CA repository
 * data in a local json file. This implementation is intended for test and evaluation
 * purposes only and SHOULD NOT be used in production.
 *
 * <p>It is highly recommended for production environments to implement a CA repository
 * based an a real database implementation with appropriate management of backup and protection
  * against conflicts and simultaneous storage and/or revocation requests</p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class MockRepoCAServices extends AbstractDefaultCAServices {

  @Autowired
  public MockRepoCAServices(InstanceConfiguration instanceConfiguration,
    PKCS11Provider pkcs11Provider, BasicServiceConfig basicServiceConfig, Map<String,
    CARepository> caRepositoryMap, ApplicationEventPublisher applicationEventPublisher) {
    super(instanceConfiguration, pkcs11Provider, basicServiceConfig, caRepositoryMap, applicationEventPublisher);
  }

  /** {@inheritDoc} */
  @Override protected AbstractBasicCA getBasicCaService(String instance, String type, PrivateKey privateKey, List<X509CertificateHolder> caChain,
    CARepository caRepository, CertificateIssuerModel certIssuerModel, CRLIssuerModel crlIssuerModel, List<String> crlDistributionPoints)
    throws NoSuchAlgorithmException {
    // Returning the same Basic CA service for any instance;
    return new MockCA(privateKey, caChain, caRepository, certIssuerModel, crlIssuerModel, crlDistributionPoints);
  }

  /** {@inheritDoc} */
  @Override protected void customizeOcspCertificateModel(DefaultCertificateModelBuilder certModelBuilder, String instance) {
    // We don't add any custom content of OCSP service certificates
  }

  /** {@inheritDoc} */
  @Override protected X509CertificateHolder generateSelfIssuedCaCert(LocalKeySource caKeySource, CAConfigData caConfigData, String instance, String baseUrl)
    throws NoSuchAlgorithmException {
    // Use the default self issued certificate implementation provided by the abstract class
    return defaultGenerateSelfIssuedCaCert(caKeySource, caConfigData);
  }

}
