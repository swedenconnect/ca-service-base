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

package se.swedenconnect.ca.service.base.configuration.health;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.List;

/**
 * Service information data used to provide service info using the /manage/info path
 */
@Data
@ToString
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CAServiceInfo {
  /** The URL of the service */
  private String serviceUrl;
  /** The configured context path */
  private String contextPath;
  /** The main port used to expose the main services (primarily CRL and OSP) */
  private int servicePort;
  /** The specific secondary internal access port */
  private int adminPort;
  /** The port used to expose manage and health data */
  private int managePort;
  /** Configuration of AJP port */
  private AJPInfo ajpConfig;
  /** Information about CA instances */
  List<CAInstanceInfo> caInstances;

  /**
   * CA instance information
   */
  @Data
  @ToString
  @Builder
  @AllArgsConstructor
  @NoArgsConstructor
  public static class CAInstanceInfo {

    /** The ID of the CA instance */
    private String id;
    /** enabled indication */
    private boolean enabled;
    /** main service type indicator */
    private String serviceType;
    /** Key source type indicator */
    private String keySourceType;
    /** Information about service key */
    private KeyInfo keyInfo;
    /** Certificate signing algorithm */
    private String algorithm;
    /** CA distinguished name */
    private String dn;
    /** CA certificate path */
    private List<String> caPath;
    /** Distribution points */
    private List<String> crlDistributionPoints;
    /** Indication if OCSP is enabled */
    private boolean oscpEnabled;
    /** OCSP info */
    private OCSPInfo ocspInfo;
  }

  /**
   * OCSP information
   */
  @Data
  @ToString
  @Builder
  @AllArgsConstructor
  @NoArgsConstructor
  public static class OCSPInfo {
    /** OCSP responder URL */
    private String ocspServiceUrl;
    /** true if the OCSP responder has its own responder certificate for a unique key, or if it operates under the CA certificate and key */
    private boolean separateEntity;
    /** OCSP entity info */
    private OCSPEntityInfo ocspEntity;
  }

  /**
   * OCSP entity information
   */
  @Data
  @ToString
  @Builder
  @AllArgsConstructor
  @NoArgsConstructor
  public static class OCSPEntityInfo {
    /** Distinguished name of OCSP responder  */
    private String dn;
    /** OCSP responder key source type */
    private String keySourceType;
    /** OCSP responder key info */
    private KeyInfo keyInfo;
    /** Algorithm used to sign OCSP responses */
    private String algorithm;
  }

  /**
   * Service key information
   */
  @Data
  @ToString
  @AllArgsConstructor
  public static class KeyInfo {
    /** Type of key */
    private String keyType;
    /** Key length */
    private int keyLength;
  }

  /**
   * AJP information
   */
  @Data
  @ToString
  @AllArgsConstructor
  public static class AJPInfo {
    /** AJP port */
    private int port;
    /** AJP secret */
    private boolean secret;
  }

}

