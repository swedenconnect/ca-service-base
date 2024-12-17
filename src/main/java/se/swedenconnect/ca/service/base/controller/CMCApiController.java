/*
 * Copyright 2024 Sweden Connect
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
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.CertificationRequest;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.asn1.cmc.RevokeRequest;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.cmc.api.CMCCaApi;
import se.swedenconnect.ca.cmc.api.CMCMessageException;
import se.swedenconnect.ca.cmc.api.CMCRequestParser;
import se.swedenconnect.ca.cmc.api.data.CMCControlObject;
import se.swedenconnect.ca.cmc.api.data.CMCRequest;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;
import se.swedenconnect.ca.cmc.auth.CMCUtils;
import se.swedenconnect.ca.cmc.model.request.CMCRequestType;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;
import se.swedenconnect.ca.service.base.ca.CAServices;
import se.swedenconnect.ca.service.base.configuration.audit.AuditCMCRequestParser;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventEnum;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventFactory;
import se.swedenconnect.ca.service.base.configuration.audit.CAAuditEventData;
import se.swedenconnect.ca.service.base.configuration.cmc.CMCPortConstraints;
import se.swedenconnect.ca.service.base.configuration.keys.BasicX509Utils;

/**
 * CMC API Controller.
 */
@Slf4j
@RestController
public class CMCApiController implements ApplicationEventPublisherAware {

  private static final String CMC_MIME_TYPE = "application/pkcs7-mime";
  private static final MultiValueMap<String, String> HEADER_MAP;

  private ApplicationEventPublisher applicationEventPublisher;
  private final Map<String, CMCCaApi> cmcCaApiMap;
  private final CMCPortConstraints cmcPortConstraints;
  private final Map<String, AuditCMCRequestParser> cmcRequestParserMap;
  private final CAServices caServices;

  static {
    HEADER_MAP = new LinkedMultiValueMap<>();
    HEADER_MAP.add("Cache-Control", "no-cache, no-store, must-revalidate");
    HEADER_MAP.add("Pragma", "no-cache");
    HEADER_MAP.add("Expires", "0");
  }

  /**
   * Bean constructor
   *
   * @param cmcCaApiMap CMC API map
   * @param cmcPortConstraints CMC port constraints handler
   * @param cmcRequestParserMap map of CMC request parsers
   * @param caServices CA services
   */
  @Autowired
  public CMCApiController(final Map<String, CMCCaApi> cmcCaApiMap, final CMCPortConstraints cmcPortConstraints,
      final Map<String, AuditCMCRequestParser> cmcRequestParserMap, final CAServices caServices) {
    this.cmcCaApiMap = cmcCaApiMap;
    this.cmcPortConstraints = cmcPortConstraints;
    this.cmcRequestParserMap = cmcRequestParserMap;
    this.caServices = caServices;
  }

  /**
   * Processing a POST CMC request for an CMC response for a given CA service instance
   *
   * @param instance the CA service instance used to generate the CMC response
   * @param requestPayload the bytes received with the POST as the payload bytes
   * @param contentType HTTP Content-Type header
   * @param request HTTP servlet request
   * @return CMC response
   */
  @PostMapping(value = "/cmc/{instance}")
  public ResponseEntity<InputStreamResource> cmcRequest(
      @PathVariable("instance") final String instance, final HttpEntity<byte[]> requestPayload,
      @RequestHeader("Content-Type") final String contentType,
      final HttpServletRequest request) {

    try {
      // Enforce port restrictions
      this.cmcPortConstraints.validateRequestPort(request);
    }
    catch (final IOException e) {
      return new ResponseEntity<>(HttpStatus.FORBIDDEN);
    }

    if (!contentType.equalsIgnoreCase(CMC_MIME_TYPE)) {
      log.debug("Received CMC post request for with illegal Content-Type {}", contentType);
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
    if (StringUtils.isBlank(instance) || !this.cmcCaApiMap.containsKey(instance)) {
      log.debug("Received CMC is not supported for specified instance {}", contentType);
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    try {
      final CMCRequestParser requestParser = this.cmcRequestParserMap.get(instance);
      final CMCRequest cmcRequest = requestParser.parseCMCrequest(requestPayload.getBody());
      final CMCRequestType cmcRequestType = cmcRequest.getCmcRequestType();
      // Log request
      if (cmcRequestType == CMCRequestType.issueCert) {
        this.auditLogIssueCertRequest(cmcRequest, instance);
      }
      else if (cmcRequestType == CMCRequestType.revoke) {
        this.auditLogRevokeRequest(cmcRequest, instance);
      }

      // Perform requested operation
      final CMCCaApi cmcCaApi = this.cmcCaApiMap.get(instance);
      final CMCResponse cmcResponse = cmcCaApi.processRequest(requestPayload.getBody());

      // Log result
      if (cmcRequestType == CMCRequestType.issueCert) {
        this.auditLogIssueCert(cmcRequest, cmcResponse, instance);
      }
      else if (cmcRequestType == CMCRequestType.revoke) {
        this.auditLogRevokeCert(cmcRequest, cmcResponse, instance);
      }

      return ResponseEntity
          .ok()
          .headers(new HttpHeaders(HEADER_MAP))
          .contentLength(cmcResponse.getCmcResponseBytes().length)
          .contentType(MediaType.parseMediaType(CMC_MIME_TYPE))
          .body(new InputStreamResource(new ByteArrayInputStream(cmcResponse.getCmcResponseBytes())));

    }
    catch (final Exception ex) {
      log.debug("Unable to parse CMC request: {}", ex.getMessage());
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
  }

  private void auditLogIssueCertRequest(final CMCRequest cmcRequest, final String instance) throws IOException {
    // Get subject name and certificate request data from CMC Request
    final CertificationRequest certificationRequest = cmcRequest.getCertificationRequest();
    final CertificateRequestMessage certificateRequestMessage = cmcRequest.getCertificateRequestMessage();
    final String subjectDn = certificationRequest != null
        ? certificationRequest.getSubject().toString()
        : certificateRequestMessage != null
            ? certificateRequestMessage.getCertTemplate().getSubject().toString()
            : "No request subject";

    // We have a request. Make an audit log event
    this.applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.certificateRequested,
        new CAAuditEventData(
            instance,
            subjectDn),
        null, "CMC-Client"));
    if (log.isTraceEnabled()) {
      final String certReqString = certificationRequest != null
          ? Base64.toBase64String(certificationRequest.getEncoded())
          : certificateRequestMessage != null
              ? Base64.toBase64String(certificateRequestMessage.getEncoded())
              : "#NULL";
      log.trace("Certifcate request for {} using request\n{}", subjectDn, certReqString);
    }
  }

  private void auditLogIssueCert(final CMCRequest cmcRequest, final CMCResponse cmcResponse, final String instance)
      throws CertificateEncodingException, IOException {

    final List<X509Certificate> returnCertificates = cmcResponse.getReturnCertificates();
    if (returnCertificates == null || returnCertificates.size() != 1) {
      log.warn("CA failed to issue certificate");
      return;
    }
    final X509CertificateHolder certificateHolder = new JcaX509CertificateHolder(returnCertificates.get(0));

    // Create certificate issuance audit log event
    this.applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.certificateIssued,
        new CAAuditEventData(
            instance,
            Base64.toBase64String(certificateHolder.getEncoded()),
            certificateHolder.getSerialNumber(),
            certificateHolder.getSubject().toString()),
        null, "CMC-Client"));

    log.info("Certificate issued to {}", certificateHolder.getSubject().toString());
    if (log.isTraceEnabled()) {
      log.trace("Issued Certificate: {}", Base64.toBase64String(certificateHolder.getEncoded()));
    }
  }

  private void auditLogRevokeRequest(final CMCRequest cmcRequest, final String instance) throws CMCMessageException {

    final PKIData pkiData = cmcRequest.getPkiData();
    final CMCControlObject cmcControlObject = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_revokeRequest,
        pkiData);
    final RevokeRequest revokeRequest = (RevokeRequest) cmcControlObject.getValue();

    // Audit log revocation request
    this.applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.revocationRequested,
        CAAuditEventData.builder()
            .caInstance(instance)
            .certSerialNumber(revokeRequest.getSerialNumber())
            .reason(0)
            .build(),
        null, "CMC-Client"));
  }

  private void auditLogRevokeCert(final CMCRequest cmcRequest, final CMCResponse cmcResponse, final String instance)
      throws IOException, ParseException, CertificateException, CMCMessageException {

    final PKIData pkiData = cmcRequest.getPkiData();
    final CMCControlObject cmcControlObject = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_revokeRequest,
        pkiData);
    final RevokeRequest revokeRequest = (RevokeRequest) cmcControlObject.getValue();

    final CMCStatusType status = cmcResponse.getResponseStatus().getStatus();
    if (!status.equals(CMCStatusType.success)) {
      log.warn("Failed to process revocation request via CMC for serial number {}", revokeRequest.getSerialNumber());
      return;
    }

    final CARepository caRepository = this.caServices.getCAService(instance).getCaRepository();
    final CertificateRecord certificate = caRepository.getCertificate(revokeRequest.getSerialNumber());
    final String subjectDn = certificate != null
        ? BasicX509Utils.getCertificate(certificate.getCertificate()).getSubjectX500Principal().toString()
        : "unknown";

    // Audit log revocation event
    this.applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.certificateRevoked,
        CAAuditEventData.builder()
            .caInstance(instance)
            .subject(subjectDn)
            .certSerialNumber(revokeRequest.getSerialNumber())
            .revocationTime(revokeRequest.getInvalidityDate().getDate())
            .reason(0)
            .build(),
        null, "CMC-Client"));

    final X509CRLHolder currentCrl = caRepository.getCRLRevocationDataProvider().getCurrentCrl();
    final Extension crlNumberExtension = currentCrl.getExtension(Extension.cRLNumber);
    final CRLNumber crlNumberFromCrl = CRLNumber.getInstance(crlNumberExtension.getParsedValue());
    log.info("Succeeded to publish new CRL with CRL number {}", crlNumberFromCrl.getCRLNumber().toString());
    // Audit log CRL publication
    this.applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.crlPublished,
        CAAuditEventData.builder()
            .crlNumber(crlNumberFromCrl.getCRLNumber())
            .build(),
        null, "CMC-Client"));
  }

  /** {@inheritDoc} */
  @Override
  public void setApplicationEventPublisher(final ApplicationEventPublisher applicationEventPublisher) {
    this.applicationEventPublisher = applicationEventPublisher;
  }
}
