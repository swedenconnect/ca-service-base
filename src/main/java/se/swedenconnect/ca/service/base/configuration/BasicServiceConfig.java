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
package se.swedenconnect.ca.service.base.configuration;

import java.io.File;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Basic service configuration.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class BasicServiceConfig {

  /** The base URL to the host of this application (URL without context path) */
  private String serviceHostUrl;

  /** The full URL to this service including context path */
  private String serviceUrl;

  /** The main data storage location for data associated with this service */
  private File dataStoreLocation;

}
