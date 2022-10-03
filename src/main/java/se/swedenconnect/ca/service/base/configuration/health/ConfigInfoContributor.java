/*
 * Copyright 2021-2022 Sweden Connect
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
package se.swedenconnect.ca.service.base.configuration.health;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.info.Info.Builder;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.stereotype.Component;

/**
 * Info contributor for the Health Service.
 */
@Component
public class ConfigInfoContributor implements InfoContributor {

  private final ServiceInfo serviceInfo;

  /**
   * Constructor
   *
   * @param serviceInfo service information
   */
  @Autowired
  public ConfigInfoContributor(final ServiceInfo serviceInfo) {
    this.serviceInfo = serviceInfo;
  }

  /**
   * Adds the policy configuration to the information released by the Spring Boot actuator info-endpoint.
   *
   * @param builder service information builder
   */
  @Override
  public void contribute(final Builder builder) {
    builder.withDetail("CA-service-information", this.serviceInfo.getCaServiceInfo());
  }
}
