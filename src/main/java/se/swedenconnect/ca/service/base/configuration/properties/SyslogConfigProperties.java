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

import lombok.Data;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import java.util.List;
import java.util.Map;

/**
 * Configuration Bean for Syslog properties for export of audit log data to syslog
 *
 * @author Stefan Santesson (stefan@aaa-sec.com)
 * @author Martin Lindström (martin.lindstrom@litsec.se)
 *
 */
@Configuration
@ConfigurationProperties(prefix = "ca-service.syslog")
@Data
@ToString
public class SyslogConfigProperties {

    /**
     * The syslog property map. Having a name of the syslog as key.
     */
    private List<SyslogConfigData> config;
    private boolean enabled;

    @Data
    public static class SyslogConfigData {
        private String host;
        private int port;
        private int facility;
        private Integer severity;
        private String loglevel;
        private boolean bsd;
        private String protocol;
        private String clienthostname;
        private String clientapp;
    }

}
