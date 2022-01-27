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

package se.swedenconnect.ca.service.base.configuration.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import se.swedenconnect.ca.service.base.configuration.properties.SyslogConfigProperties;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
public class SyslogConfig {

    private static final Logger log = LoggerFactory.getLogger(SyslogConfig.class);

    private final SyslogConfigProperties syslogConfigProperties;

    public SyslogConfig(SyslogConfigProperties syslogConfigProperties) {
        this.syslogConfigProperties = syslogConfigProperties;
    }

    @Bean(name = "syslogMessageSender")
    List<ExtSyslogMessageSender> syslogMessageSenderList() {
        List<SyslogConfigProperties.SyslogConfigData> syslogConfigList = syslogConfigProperties.getConfig();
        if (!syslogConfigProperties.isEnabled()) {
            log.info("No syslog server is configured. Logging to in memory audit log");
            return new ArrayList<>();
        }
        if (syslogConfigList.isEmpty()){
            throw new IllegalArgumentException("Syslog is configured, but no valid syslog configuration data is available");
        }

        return syslogConfigList.stream()
                .map(ExtSyslogMessageSender::new)
                .collect(Collectors.toList());
    }

}
