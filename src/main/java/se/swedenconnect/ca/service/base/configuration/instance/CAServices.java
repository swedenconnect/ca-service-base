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

package se.swedenconnect.ca.service.base.configuration.instance;

import se.swedenconnect.ca.engine.ca.issuer.CAService;

import java.util.List;

/**
 * Interface for implementing a bean that constructs and provides CA services based on current configuration data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CAServices {

  /**
   * List the keys for all available CA services
   * @return list of CA service identifying keys
   */
  List<String> getCAServiceKeys();

  /**
   * Test if the CA service is initialized and ready for use
   * @param instance name of the instance identifying the CA service instance
   * @return true if the CA service is initialized, otherwise false
   */
  boolean isServiceInitialized(String instance);

  /**
   * Test if the CA service is enabled or disabled for certificate issuance by configuration
   * @param instance name of the instance identifying the CA service instance
   * @return true if the CA service is enabled
   */
  boolean isServiceEnabled(String instance);

  /**
   * Getter for a CA service for a specified key
   * @param instance name of the instance identifying the CA service instance
   * @return CA service instance or null if no CA service match the specified instance name
   */
  CAService getCAService(String instance);

}
