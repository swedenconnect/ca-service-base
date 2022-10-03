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
package se.swedenconnect.ca.service.base.configuration.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;
import lombok.ToString;

/**
 * Configuration properties for default name of configured CA services.
 */
@Configuration
@ConfigurationProperties(prefix = "ca-service.default-name")
@Data
@ToString
public class EntityNameProperties {

  /** Country name 2-letter ISO 3166 country code. */
  private String country;

  /** Organization name. */
  private String org;

  /** Organization unit name */
  private String orgUnit;

  /** Organization identifier */
  private String orgIdentifier;

  /** Serial number attribute value carrying the organization identifier */
  private String serialNumber;

  /** Common name of the CA */
  private String commonName;

}
