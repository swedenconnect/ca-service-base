/*
 * Copyright 2023 Sweden Connect
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

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;
import lombok.ToString;

/**
 * Configuration Bean for Syslog properties for export of audit log data to syslog.
 */
@Configuration
@ConfigurationProperties(prefix = "ca-service.syslog")
@Data
@ToString
public class SyslogConfigProperties {

  /** The syslog property map. Having a name of the syslog as key. */
  private List<SyslogConfigData> config;

  /** Indicates if logging to syslog server is enabled */
  private boolean enabled;

  /**
   * Syslog config data
   */
  @Data
  public static class SyslogConfigData {

    /** Syslog host url */
    private String host;

    /** Syslog service port (TCP or UDP) */
    private int port;

    /** Facility identifier (0-23) */
    private int facility;

    /** Severity code (0-7) */
    private Integer severity;

    /** String alternative to severity. See: {@link com.cloudbees.syslog.Severity} */
    private String loglevel;

    /** Using message format RFC_3164 when set to true. Using RFC_5424 (UDP) or RFC_5425 (TCP) when false */
    private boolean bsd;

    /** udp, tcp or ssl */
    private String protocol;

    /** Name of the sending client host */
    private String clienthostname;

    /** Name of the sending client application */
    private String clientapp;
  }

}
