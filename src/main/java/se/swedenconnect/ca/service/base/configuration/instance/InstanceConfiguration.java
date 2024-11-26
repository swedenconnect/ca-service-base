/*
 * Copyright 2024 Sweden Connect
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
package se.swedenconnect.ca.service.base.configuration.instance;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import lombok.Getter;
import se.swedenconnect.ca.service.base.configuration.properties.CAConfigData;
import se.swedenconnect.ca.service.base.configuration.properties.CAServiceProperties;
import se.swedenconnect.ca.service.base.configuration.properties.EntityNameProperties;

/**
 * CA instance configuration data.
 */
@Component
public class InstanceConfiguration {

  private final CAServiceProperties caServiceProperties;
  private final EntityNameProperties defaultName;

  @Getter
  Map<String, CAConfigData> instanceConfigMap;

  /**
   * Constructor for instance configuration.
   *
   * @param caServiceProperties the configuration properties of configured CA instances
   * @param defaultName The default name elements of ca services
   */
  @Autowired
  public InstanceConfiguration(final CAServiceProperties caServiceProperties, final EntityNameProperties defaultName) {
    this.caServiceProperties = caServiceProperties;
    this.defaultName = defaultName;
    this.getConfiguration();
  }

  private void getConfiguration() {
    this.instanceConfigMap = new HashMap<>();

    final Map<String, CAConfigData> confPropMap = this.caServiceProperties.getConf();
    confPropMap.keySet().stream()
        .filter(instance -> !instance.equalsIgnoreCase("default"))
        .forEach(instance -> {
          final CAConfigData caProp = confPropMap.get(instance);
          final CAConfigData defaultCaProp = confPropMap.get("default");
          final CAConfigData caConf = new CAConfigData();
          caConf.setEnabled((Boolean) this.getValue(caProp.getEnabled(), defaultCaProp.getEnabled()));
          caConf.setCa(this.getCaConf(caProp.getCa(), defaultCaProp.getCa()));
          caConf.setOcsp(this.getOcspConf(caProp.getOcsp(), defaultCaProp.getOcsp()));
          this.instanceConfigMap.put(instance, caConf);
        });
  }

  private CAConfigData.OCSPConfig getOcspConf(final CAConfigData.OCSPConfig prop,
      final CAConfigData.OCSPConfig defaultVal) {
    final CAConfigData.OCSPConfig ocspConfig = new CAConfigData.OCSPConfig();
    ocspConfig.setAlgorithm((String) this.getValue(prop.getAlgorithm(), defaultVal.getAlgorithm()));
    ocspConfig.setEnabled((Boolean) this.getValue(prop.getEnabled(), defaultVal.getEnabled()));
    ocspConfig.setKeySource(this.getKeySource(prop.getKeySource(), defaultVal.getKeySource()));
    ocspConfig.setValidity(this.getValidityData(prop.getValidity(), defaultVal.getValidity()));
    ocspConfig.setName(this.getName(prop.getName()));
    return ocspConfig;
  }

  private CAConfigData.CaConfig getCaConf(final CAConfigData.CaConfig prop, final CAConfigData.CaConfig defaultVal) {
    final CAConfigData.CaConfig caConfig = new CAConfigData.CaConfig();
    caConfig.setAlgorithm((String) this.getValue(prop.getAlgorithm(), defaultVal.getAlgorithm()));
    caConfig.setDescription((String) this.getValue(prop.getDescription(), defaultVal.getDescription()));
    caConfig.setType((String) this.getValue(prop.getType(), defaultVal.getType()));
    caConfig.setAllowV1((Boolean) this.getValue(prop.getAllowV1(), defaultVal.getAllowV1()));
    caConfig.setSelfIssuedValidYears(
        (Integer) this.getValue(prop.getSelfIssuedValidYears(), defaultVal.getSelfIssuedValidYears()));
    caConfig.setOcspCertValidityAmount(
        (Integer) this.getValue(prop.getOcspCertValidityAmount(), defaultVal.getOcspCertValidityAmount()));
    caConfig.setKeySource(this.getKeySource(prop.getKeySource(), defaultVal.getKeySource()));
    caConfig.setValidity(this.getValidityData(prop.getValidity(), defaultVal.getValidity()));
    caConfig.setCrlValidity(this.getValidityData(prop.getCrlValidity(), defaultVal.getCrlValidity()));
    caConfig.setCustomCertStorageLocation(
        (String) this.getValue(prop.getCustomCertStorageLocation(), defaultVal.getCustomCertStorageLocation()));
    caConfig.setName(this.getName(prop.getName()));
    caConfig.setCrlMaxDurationBeforeUpgrade((Duration) this.getValue(prop.getCrlMaxDurationBeforeUpgrade(), defaultVal.getCrlMaxDurationBeforeUpgrade()));
    return caConfig;
  }

  private EntityNameProperties getName(EntityNameProperties propName) {
    propName = propName == null ? new EntityNameProperties() : propName;
    final EntityNameProperties name = new EntityNameProperties();
    name.setCountry((String) this.getValue(propName.getCountry(), this.defaultName.getCountry()));
    name.setOrg((String) this.getValue(propName.getOrg(), this.defaultName.getOrg()));
    name.setOrgUnit((String) this.getValue(propName.getOrgUnit(), this.defaultName.getOrgUnit()));
    name.setOrgIdentifier((String) this.getValue(propName.getOrgIdentifier(), this.defaultName.getOrgIdentifier()));
    name.setSerialNumber((String) this.getValue(propName.getSerialNumber(), this.defaultName.getSerialNumber()));
    name.setCommonName((String) this.getValue(propName.getCommonName(), this.defaultName.getCommonName()));
    return name;
  }

  private CAConfigData.ValidityData getValidityData(CAConfigData.ValidityData prop,
      CAConfigData.ValidityData defaultValue) {
    prop = prop == null ? new CAConfigData.ValidityData() : prop;
    defaultValue = defaultValue == null ? new CAConfigData.ValidityData() : defaultValue;

    final CAConfigData.ValidityData validityData = new CAConfigData.ValidityData();
    validityData.setStartOffsetSec((Integer) this.getValue(prop.getStartOffsetSec(), defaultValue.getStartOffsetSec()));
    validityData.setUnit((CAConfigData.ValidityUnit) this.getValue(prop.getUnit(), defaultValue.getUnit()));
    validityData.setAmount((Integer) this.getValue(prop.getAmount(), defaultValue.getAmount()));
    return validityData;
  }

  private CAConfigData.KeySourceData getKeySource(CAConfigData.KeySourceData prop,
      CAConfigData.KeySourceData defaultValue) {
    prop = prop == null ? new CAConfigData.KeySourceData() : prop;
    defaultValue = defaultValue == null ? new CAConfigData.KeySourceData() : defaultValue;

    final CAConfigData.KeySourceData keySourceData = new CAConfigData.KeySourceData();
    keySourceData.setType((CAConfigData.KeySourceType) this.getValue(prop.getType(), defaultValue.getType()));
    keySourceData.setResource((String) this.getValue(prop.getResource(), defaultValue.getResource()));
    keySourceData.setAlias((String) this.getValue(prop.getAlias(), defaultValue.getAlias()));
    keySourceData.setPass((String) this.getValue(prop.getPass(), defaultValue.getPass()));
    return keySourceData;
  }

  private Object getValue(final Object confValue, final Object defaultValue) {
    boolean hasValue = false;
    if (confValue != null) {
      if (confValue instanceof String) {
        hasValue = StringUtils.isNotBlank((String) confValue);
      }
      else {
        hasValue = true;
      }
    }

    return hasValue ? confValue : defaultValue;
  }
}
