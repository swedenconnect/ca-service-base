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
package se.swedenconnect.ca.service.base.ca.impl;

import java.util.ArrayList;
import java.util.List;

import se.swedenconnect.ca.service.base.ca.CAServices;
import se.swedenconnect.ca.service.base.configuration.instance.InstanceConfiguration;
import se.swedenconnect.ca.service.base.configuration.properties.CAConfigData;

/**
 * The first level of abstract implementation of the CAServices interface.
 *
 * The CAServices interface is designed to hold a whole set of individual CA instances based on property settings.
 */
public abstract class AbstractCAServices implements CAServices {

  /** Configuration data used to set up one or more CA service instances */
  protected final InstanceConfiguration instanceConfiguration;

  /**
   * Constructor for CA service instances
   *
   * @param instanceConfiguration configuration data
   */
  public AbstractCAServices(final InstanceConfiguration instanceConfiguration) {
    this.instanceConfiguration = instanceConfiguration;
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getCAServiceKeys() {
    return new ArrayList<>(this.instanceConfiguration.getInstanceConfigMap().keySet());
  }

  /** {@inheritDoc} */
  @Override
  public boolean isServiceEnabled(final String key) {
    if (this.instanceConfiguration.getInstanceConfigMap().containsKey(key)) {
      final CAConfigData caConfigData = this.instanceConfiguration.getInstanceConfigMap().get(key);
      return caConfigData.getEnabled();
    }
    return false;
  }
}
