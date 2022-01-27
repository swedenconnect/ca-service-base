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

package se.swedenconnect.ca.service.base.configuration.properties;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Calendar;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CAConfigData {
  Boolean enabled;
  CaConfig ca;
  OCSPConfig ocsp;


  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class CaConfig{
    String description;
    String type;
    String algorithm;
    Boolean allowV1;
    Integer selfIssuedValidYears;
    Integer ocspCertValidityAmount;
    ValidityData validity;
    ValidityData crlValidity;
    KeySourceData keySource;
    EntityNameProperties name;
  }
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OCSPConfig{
    Boolean enabled;
    String algorithm;
    ValidityData validity;
    KeySourceData keySource;
    EntityNameProperties name;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ValidityData{
    Integer startOffsetSec;
    ValidityUnit unit;
    Integer amount;
  }

  @Getter
  @AllArgsConstructor
  public enum ValidityUnit {
    M (Calendar.MINUTE),
    H (Calendar.HOUR),
    D (Calendar.DAY_OF_YEAR),
    Y (Calendar.YEAR);

    int unitType;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class KeySourceData {
    KeySourceType type;
    String resource;
    String alias;
    String pass;
    Boolean reloadableKeys;
  }

  public enum KeySourceType {
    none, create, jks, pem, pkcs11, pkcs12
  }


}
