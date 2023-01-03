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
package se.swedenconnect.ca.service.base.configuration.audit;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;

/**
 * Context listener for CA service.
 */
public class CAServiceContextListener implements ServletContextListener {

  /** Application event publisher */
  private final ApplicationEventPublisher applicationEventPublisher;

  /**
   * Constructor creating a context listener with an application event publisher.
   *
   * @param applicationEventPublisher application event publisher
   */
  public CAServiceContextListener(final ApplicationEventPublisher applicationEventPublisher) {
    this.applicationEventPublisher = applicationEventPublisher;
  }

  /** {@inheritDoc} */
  @Override
  public void contextInitialized(final ServletContextEvent servletContextEvent) {
    this.applicationEventPublisher.publishEvent(
        new AuditApplicationEvent(AuditEventFactory.DEFAULT_AUDIT_PRINCIPAL, AuditEventEnum.startup.getEventName()));
  }

  /** {@inheritDoc} */
  @Override
  public void contextDestroyed(final ServletContextEvent servletContextEvent) {
    this.applicationEventPublisher.publishEvent(
        new AuditApplicationEvent(AuditEventFactory.DEFAULT_AUDIT_PRINCIPAL, AuditEventEnum.shutdown.getEventName()));
  }
}
