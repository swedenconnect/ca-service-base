/*
 * Copyright 2021-2022 Sweden Connect
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
package se.swedenconnect.ca.service.base.controller;

import java.io.ByteArrayInputStream;
import java.util.Date;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.service.base.ca.CAServices;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventEnum;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventFactory;
import se.swedenconnect.ca.service.base.configuration.audit.CAAuditEventData;

/**
 * CRL information controller used to provide CRL data.
 */
@Slf4j
@RestController
public class CRLController implements ApplicationEventPublisherAware {

  private ApplicationEventPublisher applicationEventPublisher;
  @Value("${ca-service.config.crl-refresh-margin-seconds:60}")
  int crlRefreshMarginSeconds;
  private final CAServices caServices;

  /**
   * Bean constructor
   *
   * @param caServices CA services
   */
  @Autowired
  public CRLController(final CAServices caServices) {
    this.caServices = caServices;
  }

  /**
   * Handle requests for the latest CRL
   *
   * @param crlFileName the name of the requested CRL used as CRL file name
   * @return certificate revocation list
   */
  @RequestMapping(value = "/crl/{crlFileName}")
  public ResponseEntity<InputStreamResource> getCRL(@PathVariable("crlFileName") final String crlFileName) {
    if (StringUtils.isBlank(crlFileName) || !crlFileName.endsWith(".crl") || crlFileName.length() < 5) {
      log.debug("False request for CRL - specifying the crlFile {}", crlFileName);
      return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
    final String instance = crlFileName.substring(0, crlFileName.length() - 4);
    final CAService caService = this.caServices.getCAService(instance);
    if (caService == null) {
      log.debug("False request for CRL - specifying unknown instance through requested CRL file {}", crlFileName);
      return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
    log.trace("Request for CRL received for instance {}", instance);
    final byte[] currentCrl = this.getCurrentCrl(caService);
    log.trace("Retrieved current CRL for instance {}", instance);

    return ResponseEntity
        .ok()
        .headers(this.getHeaders(crlFileName))
        .contentLength(currentCrl.length)
        .contentType(MediaType.parseMediaType("application/octet-stream"))
        .body(new InputStreamResource(new ByteArrayInputStream(currentCrl)));
  }

  private HttpHeaders getHeaders(final String fileName) {
    final HttpHeaders headers = new HttpHeaders();
    headers.add("Cache-Control", "no-cache, no-store, must-revalidate");
    headers.add("content-disposition", "attachment; filename=" + fileName);
    headers.add("Pragma", "no-cache");
    headers.add("Expires", "0");
    return headers;
  }

  private byte[] getCurrentCrl(final CAService caService) {

    try {
      final X509CRLHolder currentCrl = caService.getCurrentCrl();
      this.validateCRL(currentCrl);
      return currentCrl.getEncoded();
    }
    catch (final Exception ex) {
      log.debug("Failed to use current stored CRL - {}", ex.getMessage());
    }

    try {
      log.debug("Attempting to publish new CRL");
      final X509CRLHolder currentCrl = caService.publishNewCrl();
      this.validateCRL(currentCrl);
      final Extension crlNumberExtension = currentCrl.getExtension(Extension.cRLNumber);
      final CRLNumber crlNumberFromCrl = CRLNumber.getInstance(crlNumberExtension.getParsedValue());
      log.info("Succeeded to publish new CRL with CRL number {}", crlNumberFromCrl.getCRLNumber().toString());
      // Audit log CRL publicatioin
      this.applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.crlPublished,
          CAAuditEventData.builder()
              .crlNumber(crlNumberFromCrl.getCRLNumber())
              .build(),
          null, AuditEventFactory.DEFAULT_AUDIT_PRINCIPAL));

      return currentCrl.getEncoded();
    }
    catch (final Exception ex) {
      log.error("Unable to publish a current CRL", ex);
      throw new RuntimeException("Unable to publish a current CRL", ex);
    }
  }

  private void validateCRL(final X509CRLHolder currentCrl) {
    final Date nextUpdate = currentCrl.getNextUpdate();
    if (nextUpdate.before(new Date(System.currentTimeMillis() + this.crlRefreshMarginSeconds * 1000L))) {
      throw new IllegalArgumentException("The current CRL has expired");
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setApplicationEventPublisher(final ApplicationEventPublisher applicationEventPublisher) {
    this.applicationEventPublisher = applicationEventPublisher;
  }
}
