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
package se.swedenconnect.ca.service.base.configuration.cmc;

import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import se.swedenconnect.ca.cmc.auth.AuthorizedCmcOperation;

/**
 * Configuration properties for the CA CMC service
 */
@Configuration
@ConfigurationProperties(prefix = "ca-service.cmc")
@Data
@ToString
public class CMCConfigProperties {

  /** CMC enabled for CA */
  private boolean enabled;

  /** HTTP ports allowed for CMC traffic */
  private List<Integer> port;

  /** CMC configuration data per CA instance */
  private Map<String, CMCConfigData> instance;

  /** Authorizations for CMC clients */
  private List<ClientAuthorization> client;

  /**
   * Configuration data for CMC API service.
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  public static class CMCConfigData {

    /** Location of CMC signer key store */
    private String location;

    /** Password for CMC signer key store */
    private String password;

    /** CMC signer key alias */
    private String alias;

    /** Algorithm used to sign CMC responses */
    private String algorithm;
  }

  /**
   * CMC Client authorization properties
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  public static class ClientAuthorization {
    /** Location of the trusted CMC client certificate */
    private String certLocation;

    /** The privileges of the CMC client */
    private Map<String, List<AuthorizedCmcOperation>> authorization;
  }

}
