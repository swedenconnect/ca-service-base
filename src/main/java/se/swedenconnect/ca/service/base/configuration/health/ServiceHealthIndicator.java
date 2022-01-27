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

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;
import org.springframework.stereotype.Component;

/**
 * Service health indicator bean.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Component
@Slf4j
public class ServiceHealthIndicator implements HealthIndicator {

    private final ServiceInfo serviceInfo;

    @Autowired
    public ServiceHealthIndicator(ServiceInfo serviceInfo) {
        this.serviceInfo = serviceInfo;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Health health() {
        try {
            serviceInfo.testConfiguration();
        } catch (RuntimeException ex){
            if (ex instanceof ServiceHealthWarningException){
                log.warn("The CA Service has a health warning: {}", ex.getMessage());
                return Health
                  .status(new Status("WARNING", ex.getMessage()))
                  .withDetails(((ServiceHealthWarningException)ex).getDetails())
                  .build();
            }
            log.warn("The CA Service has a negative health state: {}", ex.getMessage());
            return Health
                    .down()
                    .withDetail("error-message", ex.getMessage())
                    .build();
        }
        return Health.up().build();
    }

}
