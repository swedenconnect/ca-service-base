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

package se.swedenconnect.ca.service.base.controller;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
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
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventEnum;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventFactory;
import se.swedenconnect.ca.service.base.configuration.audit.CAAuditEventData;
import se.swedenconnect.ca.service.base.configuration.instance.CAServices;

import java.io.ByteArrayInputStream;
import java.util.Date;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
@RestController
public class CRLController implements ApplicationEventPublisherAware {

  private ApplicationEventPublisher applicationEventPublisher;
  @Value("${ca-service.config.crl-refresh-margin-seconds:60}")  int crlRefreshMarginSeconds;
  private final CAServices caServices;

  @Autowired
  public CRLController(CAServices caServices) {
    this.caServices = caServices;
  }

  @RequestMapping(value = "/crl/{crlFileName}")
  public ResponseEntity<InputStreamResource> getCRL(@PathVariable("crlFileName") String crlFileName) {
    if (StringUtils.isBlank(crlFileName) || !crlFileName.endsWith(".crl") || crlFileName.length() < 5) {
      log.debug("False request for CRL - specifying the crlFile {}", crlFileName);
      return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
    String instance = crlFileName.substring(0, crlFileName.length() - 4);
    CAService caService = caServices.getCAService(instance);
    if (caService == null) {
      log.debug("False request for CRL - specifying unknown instance through requested CRL file {}", crlFileName);
      return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
    log.trace("Request for CRL received for instance {}", instance);
    byte[] currentCrl = getCurrentCrl(caService);
    log.trace("Retrieved current CRL for instance {}", instance);

    return ResponseEntity
      .ok()
      .headers(getHeaders(crlFileName))
      .contentLength(currentCrl.length)
      .contentType(MediaType.parseMediaType("application/octet-stream"))
      .body(new InputStreamResource(new ByteArrayInputStream(currentCrl)));
  }

  private HttpHeaders getHeaders(String fileName) {
    HttpHeaders headers = new HttpHeaders();
    headers.add("Cache-Control", "no-cache, no-store, must-revalidate");
    headers.add("content-disposition", "attachment; filename=" + fileName);
    headers.add("Pragma", "no-cache");
    headers.add("Expires", "0");
    return headers;
  }


  private byte[] getCurrentCrl(CAService caService) {

    try {
      X509CRLHolder currentCrl = caService.getCurrentCrl();
      validateCRL(currentCrl);
      return currentCrl.getEncoded();
    } catch (Exception ex) {
      log.debug("Failed to use current stored CRL - {}", ex.getMessage());
    }

    try {
      log.debug("Attempting to publish new CRL");
      X509CRLHolder currentCrl = caService.publishNewCrl();
      validateCRL(currentCrl);
      Extension crlNumberExtension = currentCrl.getExtension(Extension.cRLNumber);
      CRLNumber crlNumberFromCrl = CRLNumber.getInstance(crlNumberExtension.getParsedValue());
      log.info("Succeeded to publish new CRL with CRL number {}", crlNumberFromCrl.getCRLNumber().toString());
      // Audit log CRL publicatioin
      applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.crlPublished,
        CAAuditEventData.builder()
          .crlNumber(crlNumberFromCrl.getCRLNumber())
          .build(), null, AuditEventFactory.DEFAULT_AUDIT_PRINCIPAL));

      return currentCrl.getEncoded();
    } catch (Exception ex) {
      log.error("Unable to publish a current CRL", ex);
      throw new RuntimeException("Unable to publish a current CRL", ex);
    }
  }

  private void validateCRL(X509CRLHolder currentCrl) {
    Date nextUpdate = currentCrl.getNextUpdate();
    if (nextUpdate.before(new Date(System.currentTimeMillis() +  crlRefreshMarginSeconds * 1000L))){
      throw new IllegalArgumentException("The current CRL has expired");
    }
  }

  @Override public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
    this.applicationEventPublisher = applicationEventPublisher;
  }
}
