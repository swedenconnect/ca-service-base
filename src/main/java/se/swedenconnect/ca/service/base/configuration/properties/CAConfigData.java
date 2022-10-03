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

import java.util.Calendar;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * CA instance configuration data.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CAConfigData {

  /** Indicates if the CA service is enabled */
  private Boolean enabled;

  /** Certificate issuance configuration */
  private CaConfig ca;

  /** OCSP responder configuration */
  private OCSPConfig ocsp;

  /**
   * Canfiguration for the certificate issuing part of the CA service
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class CaConfig {

    /** CA description */
    private String description;

    /** Type */
    private String type;

    /** Certificate signing algorithm */
    private String algorithm;

    /** Indicates if the CA may issue V1 certificates */
    private Boolean allowV1;

    /** The number of years the initial self issued CA certificate is valid */
    private Integer selfIssuedValidYears;

    /** The validity time of any certificates issued to the CAs own OCSP responder */
    private Integer ocspCertValidityAmount;

    /** Validity of issued certificates */
    private ValidityData validity;

    /** Validity of issued revocation lists */
    private ValidityData crlValidity;

    /** the key source of the CA */
    private KeySourceData keySource;

    /** The name of the CA */
    private EntityNameProperties name;

    /** path to a custom storage location for the CA repository data other than the instance data folder */
    private String customCertStorageLocation;
  }

  /**
   * OCSP configuration data.
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OCSPConfig {

    /** Indicates if the OCSP service is enabled */
    private Boolean enabled;

    /** Algorithm used to sign OCSP responses */
    private String algorithm;

    /** Validity of OCSP responses */
    private ValidityData validity;

    /** OCSP responder key source */
    private KeySourceData keySource;

    /** Name of the OCSP responder */
    private EntityNameProperties name;
  }

  /**
   * Validity data
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ValidityData {
    /**
     * the number of seconds the start validity should be adjusted compared to current time (- indicates time in the
     * past)
     */
    Integer startOffsetSec;
    /** The unit deciding validity time */
    ValidityUnit unit;
    /** The number of units of validity deciding validity time */
    Integer amount;
  }

  /**
   * Enumeration of validity units
   */
  @Getter
  @AllArgsConstructor
  public enum ValidityUnit {
    /** Minute */
    M(Calendar.MINUTE),
    /** Hour */
    H(Calendar.HOUR),
    /** Day */
    D(Calendar.DAY_OF_YEAR),
    /** Year */
    Y(Calendar.YEAR);

    /** The {@link Calendar} constant of the time unit */
    private final int unitType;
  }

  /**
   * Key source configuration
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class KeySourceData {
    /** Key source type */
    KeySourceType type;
    /** Identifier of the resource holding the key data */
    String resource;
    /** The alias of the key */
    String alias;
    /** Password */
    String pass;
  }

  /**
   * Key source type
   */
  public enum KeySourceType {
    /** No key source */
    none,
    /** Create a new key source */
    create,
    /** JKS key store */
    jks,
    /** PEM formatted keys, optionally encrypted private key */
    pem,
    /** PKCS11 provider linked to a HSM device */
    pkcs11,
    /** PKCS12 Key store */
    pkcs12
  }

}
