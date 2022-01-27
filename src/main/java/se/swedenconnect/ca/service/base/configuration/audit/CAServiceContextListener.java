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

import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class CAServiceContextListener implements ServletContextListener {

    private ApplicationEventPublisher applicationEventPublisher;

    public CAServiceContextListener(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        applicationEventPublisher.publishEvent(new AuditApplicationEvent(AuditEventFactory.DEFAULT_AUDIT_PRINCIPAL, AuditEventEnum.startup.getEventName()));
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
        applicationEventPublisher.publishEvent(new AuditApplicationEvent(AuditEventFactory.DEFAULT_AUDIT_PRINCIPAL, AuditEventEnum.shutdown.getEventName()));
    }
}
