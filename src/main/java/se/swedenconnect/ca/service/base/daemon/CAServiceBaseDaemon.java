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

package se.swedenconnect.ca.service.base.daemon;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventEnum;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventFactory;
import se.swedenconnect.ca.service.base.configuration.audit.CAAuditEventData;
import se.swedenconnect.ca.service.base.configuration.instance.CAServices;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

/**
 * Daemon performing timed events of the CA service base application
 *
 * ca-service.config.remove-expired-certs=false;
 * ca-service.config.remove-expired-grace-seconds=86400;
 * ca-service.config.daemon-timer-seconds=300;
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Component
@Slf4j
public class CAServiceBaseDaemon implements ApplicationEventPublisherAware, InitializingBean {

  private ApplicationEventPublisher applicationEventPublisher;
  private final boolean deleteExpired;
  private final int gracePeriodSeconds;
  private final CAServices caServices;

  @Autowired
  public CAServiceBaseDaemon(CAServices caServices,
    @Value("${ca-service.config.remove-expired-certs}") boolean deleteExpired,
    @Value("${ca-service.config.remove-expired-grace-seconds}") int gracePeriodSeconds,
    @Value("${ca-service.config.daemon-timer-seconds}") int daemonTimerSeconds) {
    this.caServices = caServices;
    this.deleteExpired = deleteExpired;
    this.gracePeriodSeconds = gracePeriodSeconds;

    log.info("Daemon setup:");
    log.info("Daemon timer seconds: {}", daemonTimerSeconds);
    log.info("Delete expired certificates: {}", deleteExpired);
    if (deleteExpired){
      log.info("Grace period seconds from expiry to delete from CA: {}", gracePeriodSeconds);
    }
  }

  @Scheduled(initialDelayString = "${ca-service.config.daemon-timer-seconds}" + "000",
    fixedDelayString = "${ca-service.config.daemon-timer-seconds}" + "000")
  public synchronized void deleteExpiredCertificates() throws IOException {
    if (deleteExpired){
      log.info("Daemon - Deleting expired certificates from CA databases");
      final List<String> caServiceInstanceList = caServices.getCAServiceKeys();
      for (String instance : caServiceInstanceList) {
        log.debug("Attempting to delete expired certificates from CA instance {}", instance);
        final CAService caService = caServices.getCAService(instance);
        final List<BigInteger> deletedCertSerials = caService.getCaRepository().removeExpiredCerts(gracePeriodSeconds);
        if (log.isDebugEnabled()){
          log.debug("{} expired certificates was deleted", deletedCertSerials.size());
        }
        if (deletedCertSerials != null) {
          // Log any deleted certificates to audit logger
          for (BigInteger certSerial : deletedCertSerials) {
            applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.expiredCertDeleted,
              CAAuditEventData.builder()
                .caInstance(instance)
                .certSerialNumber(certSerial)
                .build(), null, AuditEventFactory.DEFAULT_AUDIT_PRINCIPAL));
            log.debug("Deleted expired certificate with serial number: {}", certSerial.toString(16));
          }
        }
      }
    }
  }

  /**
   * Initial processing
   * @throws Exception on errors during initial setup
   */
  @Override public void afterPropertiesSet() throws Exception {
    log.info("Running initial daemon pass to remove expired certificates");
    deleteExpiredCertificates();
  }

    @Override public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
    this.applicationEventPublisher = applicationEventPublisher;
  }
}
