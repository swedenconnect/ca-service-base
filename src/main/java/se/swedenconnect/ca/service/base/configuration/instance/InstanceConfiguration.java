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

package se.swedenconnect.ca.service.base.configuration.instance;

import lombok.Getter;
import org.apache.commons.lang.StringUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import se.swedenconnect.ca.service.base.configuration.properties.CAConfigData;
import se.swedenconnect.ca.service.base.configuration.properties.CAServiceProperties;
import se.swedenconnect.ca.service.base.configuration.properties.EntityNameProperties;

import java.util.HashMap;
import java.util.Map;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Component
public class InstanceConfiguration {

  private final CAServiceProperties caServiceProperties;
  private final EntityNameProperties defaultName;

  @Getter Map<String, CAConfigData> instanceConfigMap;

  public InstanceConfiguration(CAServiceProperties caServiceProperties,
    EntityNameProperties defaultName) {
    this.caServiceProperties = caServiceProperties;
    this.defaultName = defaultName;
    getConfiguration();
  }

  private void getConfiguration() {
    instanceConfigMap = new HashMap<>();

    Map<String, CAConfigData> confPropMap = caServiceProperties.getConf();
    confPropMap.keySet().stream()
      .filter(instance -> !instance.equalsIgnoreCase("default"))
      .forEach(instance -> {
        CAConfigData caProp = confPropMap.get(instance);
        CAConfigData defaultCaProp = confPropMap.get("default");
        CAConfigData caConf = new CAConfigData();
        caConf.setEnabled((Boolean) getValue(caProp.getEnabled(), defaultCaProp.getEnabled()));
        caConf.setCa(getCaConf(caProp.getCa(), defaultCaProp.getCa()));
        caConf.setOcsp(getOcspConf(caProp.getOcsp(), defaultCaProp.getOcsp()));
        instanceConfigMap.put(instance, caConf);
      });

    int sdf = 0;
  }

  private CAConfigData.OCSPConfig getOcspConf(CAConfigData.OCSPConfig prop, CAConfigData.OCSPConfig defaultVal) {
    CAConfigData.OCSPConfig ocspConfig = new CAConfigData.OCSPConfig();
    ocspConfig.setAlgorithm((String) getValue(prop.getAlgorithm(), defaultVal.getAlgorithm()));
    ocspConfig.setEnabled((Boolean) getValue(prop.getEnabled(), defaultVal.getEnabled()));
    ocspConfig.setKeySource(getKeySource(prop.getKeySource(), defaultVal.getKeySource()));
    ocspConfig.setValidity(getValidityData(prop.getValidity(), defaultVal.getValidity()));
    ocspConfig.setName(getName(prop.getName()));
    return ocspConfig;
  }

  private CAConfigData.CaConfig getCaConf(CAConfigData.CaConfig prop, CAConfigData.CaConfig defaultVal) {
    CAConfigData.CaConfig caConfig = new CAConfigData.CaConfig();
    caConfig.setAlgorithm((String) getValue(prop.getAlgorithm(), defaultVal.getAlgorithm()));
    caConfig.setDescription((String) getValue(prop.getDescription(), defaultVal.getDescription()));
    caConfig.setType((String) getValue(prop.getType(), defaultVal.getType()));
    caConfig.setAllowV1((Boolean) getValue(prop.getAllowV1(), defaultVal.getAllowV1()));
    caConfig.setSelfIssuedValidYears((Integer) getValue(prop.getSelfIssuedValidYears(), defaultVal.getSelfIssuedValidYears()));
    caConfig.setOcspCertValidityAmount((Integer) getValue(prop.getOcspCertValidityAmount(), defaultVal.getOcspCertValidityAmount()));
    caConfig.setKeySource(getKeySource(prop.getKeySource(), defaultVal.getKeySource()));
    caConfig.setValidity(getValidityData(prop.getValidity(), defaultVal.getValidity()));
    caConfig.setCrlValidity(getValidityData(prop.getCrlValidity(), defaultVal.getCrlValidity()));
    caConfig.setName(getName(prop.getName()));
    return caConfig;
  }

  private EntityNameProperties getName(EntityNameProperties propName) {
    propName = propName == null ? new EntityNameProperties() : propName;
    EntityNameProperties name = new EntityNameProperties();
    name.setCountry((String) getValue(propName.getCountry(), defaultName.getCountry()));
    name.setOrg((String) getValue(propName.getOrg(), defaultName.getOrg()));
    name.setOrgUnit((String) getValue(propName.getOrgUnit(), defaultName.getOrgUnit()));
    name.setOrgIdentifier((String) getValue(propName.getOrgIdentifier(), defaultName.getOrgIdentifier()));
    name.setSerialNumber((String) getValue(propName.getSerialNumber(), defaultName.getSerialNumber()));
    name.setCommonName((String) getValue(propName.getCommonName(), defaultName.getCommonName()));
    return name;
  }

  private CAConfigData.ValidityData getValidityData(CAConfigData.ValidityData prop, CAConfigData.ValidityData defaultValue) {
    prop = prop == null ? new CAConfigData.ValidityData() : prop;
    defaultValue = defaultValue == null ? new CAConfigData.ValidityData() : defaultValue;

    CAConfigData.ValidityData validityData = new CAConfigData.ValidityData();
    validityData.setStartOffsetSec((Integer) getValue(prop.getStartOffsetSec(), defaultValue.getStartOffsetSec()));
    validityData.setUnit((CAConfigData.ValidityUnit) getValue(prop.getUnit(), defaultValue.getUnit()));
    validityData.setAmount((Integer) getValue(prop.getAmount(), defaultValue.getAmount()));
    return validityData;
  }

  private CAConfigData.KeySourceData getKeySource(CAConfigData.KeySourceData prop, CAConfigData.KeySourceData defaultValue) {
    prop = prop == null ? new CAConfigData.KeySourceData() : prop;
    defaultValue = defaultValue == null ? new CAConfigData.KeySourceData() : defaultValue;

    CAConfigData.KeySourceData keySourceData = new CAConfigData.KeySourceData();
    keySourceData.setType((CAConfigData.KeySourceType) getValue(prop.getType(), defaultValue.getType()));
    keySourceData.setResource((String) getValue(prop.getResource(), defaultValue.getResource()));
    keySourceData.setAlias((String) getValue(prop.getAlias(), defaultValue.getAlias()));
    keySourceData.setPass((String) getValue(prop.getPass(), defaultValue.getPass()));
    keySourceData.setReloadableKeys((Boolean) getValue(prop.getReloadableKeys(), defaultValue.getReloadableKeys()));
    return keySourceData;
  }

  private Object getValue(Object confValue, Object defaultValue) {
    boolean hasValue = false;
    if (confValue != null){
      if (confValue instanceof String){
        hasValue = StringUtils.isNotBlank((String) confValue);
      } else {
        hasValue = true;
      }
    }

    return hasValue ? confValue : defaultValue;
  }
}
