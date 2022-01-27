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

import lombok.*;

import java.util.List;

/**
 * Service information data used to provide service info using the /manage/info path
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@ToString
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CAServiceInfo {
  private String serviceUrl;
  private String contextPath;
  private int servicePort;
  private int adminPort;
  private int managePort;
  private AJPInfo ajpConfig;
  List<CAInstanceInfo> caInstances;

  @Data
  @ToString
  @Builder
  @AllArgsConstructor
  @NoArgsConstructor
  public static class CAInstanceInfo {

    private String id;
    private boolean enabled;
    private String serviceType;
    private String keySourceType;
    private KeyInfo keyInfo;
    private String algorithm;
    private String dn;
    private List<String> caPath;
    private List<String> crlDistributionPoints;
    private boolean oscpEnabled;
    private OCSPInfo ocspInfo;
  }

  @Data
  @ToString
  @Builder
  @AllArgsConstructor
  @NoArgsConstructor
  public static class OCSPInfo {
    private String ocspServiceUrl;
    private boolean separateEntity;
    private OCSPEntityInfo ocspEntity;
  }
  @Data
  @ToString
  @Builder
  @AllArgsConstructor
  @NoArgsConstructor
  public static class OCSPEntityInfo {
    private String dn;
    private String keySourceType;
    private KeyInfo keyInfo;
    private String algorithm;
  }

  @Data
  @ToString
  @AllArgsConstructor
  public static class KeyInfo {
    private String keyType;
    private int keyLength;
  }

  @Data
  @ToString
  @AllArgsConstructor
  public static class AJPInfo {
    private int port;
    private boolean secret;
  }

}

