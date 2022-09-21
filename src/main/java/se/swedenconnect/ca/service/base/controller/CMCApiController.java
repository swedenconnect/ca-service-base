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
import se.swedenconnect.ca.service.base.configuration.audit.AuditCMCRequestParser;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventEnum;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventFactory;
import se.swedenconnect.ca.service.base.configuration.audit.CAAuditEventData;
import se.swedenconnect.ca.service.base.configuration.cmc.CMCPortConstraints;
import se.swedenconnect.ca.service.base.configuration.instance.CAServices;
import se.swedenconnect.ca.service.base.configuration.keys.BasicX509Utils;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
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

  @Autowired
  public CMCApiController(Map<String, CMCCaApi> cmcCaApiMap, CMCPortConstraints cmcPortConstraints,
    Map<String, AuditCMCRequestParser> cmcRequestParserMap, CAServices caServices) {
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
   * @return CMC response
   */
  @PostMapping(value = "/cmc/{instance}")
  public ResponseEntity<InputStreamResource> cmcRequest(
    @PathVariable("instance") String instance, HttpEntity<byte[]> requestPayload,
    @RequestHeader("Content-Type") String contentType,
    HttpServletRequest request) {

    try {
      // Enforce port restrictions
      cmcPortConstraints.validateRequestPort(request);
    }
    catch (IOException e) {
      return new ResponseEntity<>(HttpStatus.FORBIDDEN);
    }

    if (!contentType.equalsIgnoreCase(CMC_MIME_TYPE)) {
      log.debug("Received CMC post request for with illegal Content-Type {}", contentType);
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
    if (StringUtils.isBlank(instance) || !cmcCaApiMap.containsKey(instance)) {
      log.debug("Received CMC is not supported for specified instance {}", contentType);
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    try {
      final CMCRequestParser requestParser = cmcRequestParserMap.get(instance);
      final CMCRequest cmcRequest = requestParser.parseCMCrequest(requestPayload.getBody());
      final CMCRequestType cmcRequestType = cmcRequest.getCmcRequestType();
      // Log request
      switch (cmcRequestType) {
      case issueCert:
        auditLogIssueCertRequest(cmcRequest, instance);
        break;
      case revoke:
        auditLogRevokeRequest(cmcRequest, instance);
        break;
      }

      // Perform requested operation
      final CMCCaApi cmcCaApi = cmcCaApiMap.get(instance);
      final CMCResponse cmcResponse = cmcCaApi.processRequest(requestPayload.getBody());

      // Log result
      switch (cmcRequestType) {
      case issueCert:
        auditLogIssueCert(cmcRequest, cmcResponse, instance);
        break;
      case revoke:
        auditLogRevokeCert(cmcRequest, cmcResponse, instance);
        break;
      }

      return ResponseEntity
        .ok()
        .headers(new HttpHeaders(HEADER_MAP))
        .contentLength(cmcResponse.getCmcResponseBytes().length)
        .contentType(MediaType.parseMediaType(CMC_MIME_TYPE))
        .body(new InputStreamResource(new ByteArrayInputStream(cmcResponse.getCmcResponseBytes())));

    }
    catch (Exception ex) {
      log.debug("Unable to parse CMC request: {}", ex.getMessage());
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
  }

  private void auditLogIssueCertRequest(CMCRequest cmcRequest, String instance) throws IOException {
    // Get subject name and certificate request data from CMC Request
    CertificationRequest certificationRequest = cmcRequest.getCertificationRequest();
    CertificateRequestMessage certificateRequestMessage = cmcRequest.getCertificateRequestMessage();
    String subjectDn = certificationRequest != null
      ? certificationRequest.getSubject().toString()
      : certificateRequestMessage != null
      ? certificateRequestMessage.getCertTemplate().getSubject().toString()
      : "No request subject";

    // We have a request. Make an audit log event
    applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.certificateRequested,
      new CAAuditEventData(
        instance,
        subjectDn),
      null, "CMC-Client"));
    if (log.isTraceEnabled()) {
      String certReqString = certificationRequest != null
        ? Base64.toBase64String(certificationRequest.getEncoded())
        : certificateRequestMessage != null
        ? Base64.toBase64String(certificateRequestMessage.getEncoded())
        : "#NULL";
      log.trace("Certifcate request for {} using request\n{}", subjectDn, certReqString);
    }
  }

  private void auditLogIssueCert(CMCRequest cmcRequest, CMCResponse cmcResponse, String instance)
    throws CertificateEncodingException, IOException {

    final List<X509Certificate> returnCertificates = cmcResponse.getReturnCertificates();
    if (returnCertificates == null || returnCertificates.size() != 1) {
      log.warn("CA failed to issue certificate");
      return;
    }
    X509CertificateHolder certificateHolder = new JcaX509CertificateHolder(returnCertificates.get(0));

    //Create certificate issuance audit log event
    applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.certificateIssued,
      new CAAuditEventData(
        instance,
        Base64.toBase64String(certificateHolder.getEncoded()),
        certificateHolder.getSerialNumber(),
        certificateHolder.getSubject().toString()
      ), null, "CMC-Client"));

    log.info("Certificate issued to {}", certificateHolder.getSubject().toString());
    if (log.isTraceEnabled()) {
      log.trace("Issued Certificate: {}", Base64.toBase64String(certificateHolder.getEncoded()));
    }
  }

  private void auditLogRevokeRequest(CMCRequest cmcRequest, String instance) throws CMCMessageException {

    PKIData pkiData = cmcRequest.getPkiData();
    CMCControlObject cmcControlObject = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_revokeRequest,
      pkiData);
    RevokeRequest revokeRequest = (RevokeRequest) cmcControlObject.getValue();

    //Audit log revocation request
    applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.revocationRequested,
      CAAuditEventData.builder()
        .caInstance(instance)
        .certSerialNumber(revokeRequest.getSerialNumber())
        .reason(0)
        .build(), null, "CMC-Client"));
  }

  private void auditLogRevokeCert(CMCRequest cmcRequest, CMCResponse cmcResponse, String instance)
    throws IOException, ParseException, CertificateException, CMCMessageException {

    PKIData pkiData = cmcRequest.getPkiData();
    CMCControlObject cmcControlObject = CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_revokeRequest,
      pkiData);
    RevokeRequest revokeRequest = (RevokeRequest) cmcControlObject.getValue();

    final CMCStatusType status = cmcResponse.getResponseStatus().getStatus();
    if (!status.equals(CMCStatusType.success)) {
      log.warn("Failed to process revocation request via CMC for serial number {}", revokeRequest.getSerialNumber());
      return;
    }

    final CARepository caRepository = caServices.getCAService(instance).getCaRepository();
    final CertificateRecord certificate = caRepository.getCertificate(revokeRequest.getSerialNumber());
    String subjectDn = certificate != null
      ? BasicX509Utils.getCertificate(certificate.getCertificate()).getSubjectX500Principal().toString()
      : "unknown";

    //Audit log revocation event
    applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.certificateRevoked,
      CAAuditEventData.builder()
        .caInstance(instance)
        .subject(subjectDn)
        .certSerialNumber(revokeRequest.getSerialNumber())
        .revocationTime(revokeRequest.getInvalidityDate().getDate())
        .reason(0)
        .build(), null, "CMC-Client"));

    final X509CRLHolder currentCrl = caRepository.getCRLRevocationDataProvider().getCurrentCrl();
    Extension crlNumberExtension = currentCrl.getExtension(Extension.cRLNumber);
    CRLNumber crlNumberFromCrl = CRLNumber.getInstance(crlNumberExtension.getParsedValue());
    log.info("Succeeded to publish new CRL with CRL number {}", crlNumberFromCrl.getCRLNumber().toString());
    // Audit log CRL publication
    applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.crlPublished,
      CAAuditEventData.builder()
        .crlNumber(crlNumberFromCrl.getCRLNumber())
        .build(), null, "CMC-Client"));
  }

  @Override public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
    this.applicationEventPublisher = applicationEventPublisher;
  }
}
