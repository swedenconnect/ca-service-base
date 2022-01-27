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

package se.swedenconnect.ca.service.base.configuration.instance.impl;

import se.swedenconnect.ca.service.base.configuration.instance.CAServices;
import se.swedenconnect.ca.service.base.configuration.instance.InstanceConfiguration;
import se.swedenconnect.ca.service.base.configuration.properties.CAConfigData;

import java.util.ArrayList;
import java.util.List;

/**
 * The first level of abstract implementation of the CAServices interface
 *
 * The CAServices interface is designed to hold a whole set of individual CA instances
 * based on property settings
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractCAServices implements CAServices {

  protected final InstanceConfiguration instanceConfiguration;

  public AbstractCAServices(InstanceConfiguration instanceConfiguration){
    this.instanceConfiguration = instanceConfiguration;
  }

  /** {@inheritDoc} */
  @Override public List<String> getCAServiceKeys() {
    return new ArrayList<>(instanceConfiguration.getInstanceConfigMap().keySet());
  }

  /** {@inheritDoc} */
  @Override public boolean isServiceEnabled(String key) {
    if (instanceConfiguration.getInstanceConfigMap().containsKey(key)){
      CAConfigData caConfigData = instanceConfiguration.getInstanceConfigMap().get(key);
      return caConfigData.getEnabled();
    }
    return false;
  }
}
