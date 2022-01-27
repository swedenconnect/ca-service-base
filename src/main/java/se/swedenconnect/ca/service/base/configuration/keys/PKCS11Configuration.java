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

package se.swedenconnect.ca.service.base.configuration.keys;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import se.swedenconnect.opensaml.pkcs11.PKCS11Provider;
import se.swedenconnect.opensaml.pkcs11.PKCS11ProviderFactory;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11ProvidedCfgConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11ProviderConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.PKCS11SoftHsmProviderConfiguration;
import se.swedenconnect.opensaml.pkcs11.configuration.SoftHsmCredentialConfiguration;

import java.io.File;
import java.security.Provider;
import java.security.Security;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
@Configuration
public class PKCS11Configuration {

  @Bean
  PKCS11Provider pkcs11Provider(
    @Value("${ca-service.pkcs11.external-config-locations:#{null}}") String hsmExternalCfgLocations,
    @Value("${ca-service.pkcs11.lib:#{null}}") String hsmLib,
    @Value("${ca-service.pkcs11.name:#{null}}") String hsmProviderName,
    @Value("${ca-service.pkcs11.slot:#{null}}") String hsmSlot,
    @Value("${ca-service.pkcs11.slotListIndex:#{null}}") Integer hsmSlotListIndex,
    @Value("${ca-service.pkcs11.slotListIndexMaxRange:#{null}}") Integer hsmSlotListIndexMaxRange,
    @Value("${ca-service.pkcs11.softhsm.keylocation:#{null}}") String hsmKeyLocation,
    @Value("${ca-service.pkcs11.softhsm.pass:#{null}}") String hsmPin

  ) throws Exception {
    PKCS11ProviderConfiguration configuration;
    if (hsmExternalCfgLocations != null) {
      configuration = new PKCS11ProvidedCfgConfiguration(Collections.singletonList(hsmExternalCfgLocations));
      log.info("Setting up PKCS11 configuration based on externally provided PKCS11 config files");
    }
    else {
      if (hsmKeyLocation != null && hsmPin != null) {
        PKCS11SoftHsmProviderConfiguration softHsmConfig = new PKCS11SoftHsmProviderConfiguration();
        softHsmConfig.setCredentialConfigurationList(getCredentialConfiguration(hsmKeyLocation));
        softHsmConfig.setPin(hsmPin);
        configuration = softHsmConfig;
        log.info("Setting up PKCS11 configuration based on SoftHSM");
      }
      else {
        configuration = new PKCS11ProviderConfiguration();
        log.info("Setting up generic PKCS11 configuration");
      }
      configuration.setLibrary(hsmLib);
      configuration.setName(hsmProviderName);
      configuration.setSlot(hsmSlot);
      configuration.setSlotListIndex(hsmSlotListIndex);
      configuration.setSlotListIndexMaxRange(hsmSlotListIndexMaxRange);
    }

    PKCS11ProviderFactory factory = new PKCS11ProviderFactory(configuration, configString -> {
      Provider sunPKCS11 = Security.getProvider("SunPKCS11");
      // In Java 9+ the config string is either a file path (providing the config data) or the actual config data preceded with "--".
      sunPKCS11 = sunPKCS11.configure("--" + configString);
      return sunPKCS11;
    });
    return factory.createInstance();
  }

  private List<SoftHsmCredentialConfiguration> getCredentialConfiguration(String hsmKeyLocation) {
    File keyDir = new File(hsmKeyLocation);
    File[] files = keyDir.listFiles((dir, name) -> name.endsWith(".key") || name.endsWith(".crt"));
    assert files != null;
    List<File> keyList = Arrays.stream(files)
      .filter(file -> file.getName().endsWith(".key"))
      .collect(Collectors.toList());
    List<String> certList = Arrays.stream(files)
      .filter(file -> file.getName().endsWith(".crt"))
      .filter(file -> isKeyMatch(file, keyList))
      .map(file -> file.getName().substring(0, file.getName().length() - 4))
      .collect(Collectors.toList());

    List<SoftHsmCredentialConfiguration> credentialConfigurationList = new ArrayList<>();
    certList.forEach(keyName -> {
      SoftHsmCredentialConfiguration cc = new SoftHsmCredentialConfiguration();
      cc.setName(keyName);
      cc.setKeyLocation(new File(hsmKeyLocation, keyName + ".key").getAbsolutePath());
      cc.setCertLocation(new File(hsmKeyLocation, keyName + ".crt").getAbsolutePath());
      credentialConfigurationList.add(cc);
    });
    return credentialConfigurationList;
  }

  private boolean isKeyMatch(File file, List<File> keyList) {
    String name = file.getName().substring(0, file.getName().length() - 4);
    return keyList.stream()
      .anyMatch(f -> f.getName().equalsIgnoreCase(name + ".key"));
  }

}
