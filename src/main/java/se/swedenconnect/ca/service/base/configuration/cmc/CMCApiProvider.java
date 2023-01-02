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
package se.swedenconnect.ca.service.base.configuration.cmc;

import se.swedenconnect.ca.cmc.api.CMCCaApi;
import se.swedenconnect.ca.cmc.api.CMCRequestParser;
import se.swedenconnect.ca.cmc.api.CMCResponseFactory;
import se.swedenconnect.ca.cmc.api.impl.DefaultCMCCaApi;
import se.swedenconnect.ca.engine.ca.issuer.CAService;

/**
 * This provider is used to obtain the specific implementation of the CMC CA API that is to be used for a particular CA
 * Service.
 *
 * This interface creates a suitable provider for a specified CA instances.
 *
 * The difference between different CMC CA API implementations lies mainly in how certificate request data is used to
 * determine certificate content. The default implementation {@link DefaultCMCCaApi} simply trust the certificate
 * request data to be complete and faithfully issue a certificate exactly as requested.
 *
 * If some other procedure is used to validate och modify certificate request data, then this provider implementation
 * must return a CMC CA API implementation that enforces those rules.
 */
public interface CMCApiProvider {

  /**
   * Provide a suitable CMCCaApi implementation
   *
   * @param instance instance name of the CA
   * @param caService the CA service
   * @param requestParser parser of CMC requests
   * @param responseFactory CMC response factory
   * @return {@link CMCCaApi}
   */
  CMCCaApi getCmcCaApi(final String instance, final CAService caService,
      final CMCRequestParser requestParser, final CMCResponseFactory responseFactory);
}
