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
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.ca.service.base.configuration.instance.CAServices;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@RestController
@Slf4j
public class OCSPController {

  @Value("${ca-service.config.enforce-ocsp-content-type:true}") boolean enforceOcspContentType;
  private final CAServices caServices;
  private static final MultiValueMap<String,String> headerMap;

  static {
    headerMap = new LinkedMultiValueMap<>();
    headerMap.add("Cache-Control", "no-cache, no-store, must-revalidate");
    headerMap.add("Pragma", "no-cache");
    headerMap.add("Expires", "0");
  }

  @Autowired
  public OCSPController(CAServices caServices) {
    this.caServices = caServices;
  }

  /**
   * Processing a POST request for an OCSP response for a given CA service instance
   * @param instance the CA service instance used to generate the OCSP response
   * @param requestPayload the bytes received with the POST as the payload bytes
   * @param contentType HTTP Content-Type header
   * @return OCSP response
   */
  @PostMapping(value = "/ocsp/{instance}")
  public ResponseEntity<InputStreamResource> ocspPostRespondse(
    @PathVariable("instance") String instance, HttpEntity<byte[]> requestPayload,
    @RequestHeader("Content-Type") String contentType,
    HttpServletRequest request) {
    if (!contentType.equalsIgnoreCase("application/ocsp-request") && enforceOcspContentType){
      log.debug("Received post request for OCSP response with illegal Content-Type {}", contentType);
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
    try {
      return getOCSPResponse(requestPayload.getBody(), instance, request);
    } catch (Exception ex) {
      log.debug("Unable to parse OCSP POST request: {}", ex.getMessage());
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
  }

  /**
   * The GET support of OCSP is disabled as it turns out to be highly unreliable due to the OCSP specification syntax url/{base64(ocspreq)}
   * It turns out that Spring Boot URL decodes the URL before doing path mapping. This means that the OCSP request sometimes introduces
   * new "/" signs which is part of Base64 as well as a possible number 0-9 trailing the /. This ends up being an illegal URL
   * To fix this issue we would have to alter Spring Boot Filter for URL processing and stop URL Decoding. Since HTTP GET with
   * OCSP is practically unused, this is not worth it at this point. The code below could be fixed in some future release.
   *
   * Processing a GET request for an OCSP response in accordance with RFC 6960
   *
   * <p>Request length of more than 255 bytes SHOULD be sent using POST request, but we allow longer requests as long as they
   * are successfully received as part of the encoded URL</p>
   *
   * @param instance the CA Service instance used to generate the OCSP response
   * @return OCSP response bytes
   */
/*  @GetMapping(value = "/ocsp/{instance}/**")
  public ResponseEntity<InputStreamResource> ocspGetResponse(
    @PathVariable("instance") String instance,
    HttpServletRequest request
  ) {
    try {
      final StringBuffer requestURL = request.getRequestURL();
      String reqPrefix = "/ocsp/"+instance+"/";
      String b64OcspReq = requestURL.substring(requestURL.indexOf(reqPrefix) + reqPrefix.length());
      // RFC 6960 recommends the GET is not used if request is larger than 255 bytes. We allow more, but set a maximum limit of 10K to defend against attacks.
      if (b64OcspReq.length() > 10000){
        throw new RuntimeException("Too long OCSP GET request");
      }
      // The base64 request was URL encoded, but this has already been decoded to Base64 by Spring
      byte[] ocspRequestBytes = Base64.decode(b64OcspReq);
      return getOCSPResponse(ocspRequestBytes, instance, request);

    } catch (Exception ex) {
      log.debug("Unable to parse OCSP GET request: {}", ex.getMessage());
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
  }*/

  private ResponseEntity<InputStreamResource> getOCSPResponse(byte[] ocspRequestBytes, String instance, HttpServletRequest request) throws IOException {
    CAService caService = caServices.getCAService(instance);
    if (caService == null) {
      log.debug("OCSP request for unknown CA instance");
      return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
    OCSPResponder ocspResponder = caService.getOCSPResponder();
    if (ocspResponder == null) {
      log.debug("Request fro OCSP response but OCSP responder is not available for instance {}", instance);
      return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
    if (ocspRequestBytes.length > 10000){
      log.debug("OCSP of length {} exceeds maximum size of 10 KBytes", ocspRequestBytes.length);
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    OCSPRequest ocspRequest = OCSPRequest.getInstance(new ASN1InputStream(ocspRequestBytes).readObject());
    byte[] ocspResp = ocspResponder.handleRequest(ocspRequest).getEncoded();
    if (log.isDebugEnabled()){
      String clientIp = getRemoteIpAdress(request);
      log.debug("Generated and returning OCSP response for instance {} from IP {}", instance, clientIp);
    }

    return ResponseEntity
      .ok()
      .headers(new HttpHeaders(headerMap))
      .contentLength(ocspResp.length)
      .contentType(MediaType.parseMediaType("application/ocsp-response"))
      .body(new InputStreamResource(new ByteArrayInputStream(ocspResp)));
  }

  /**
   * Retrieves the original client IP-adress. Chooses the X-FORWARDED-FOR adress if present or
   * Otherwise chooses the originating ip address.
   * @param request The HttpServlet request
   * @return The remote ip address
   */
  public static final String getRemoteIpAdress(HttpServletRequest request){
    String ipAddress = request.getHeader("X-FORWARDED-FOR");
    if (ipAddress == null) {
      ipAddress = request.getRemoteAddr();
    }
    return ipAddress;
  }

}
