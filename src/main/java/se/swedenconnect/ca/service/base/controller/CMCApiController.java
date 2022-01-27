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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import se.swedenconnect.ca.cmc.api.CMCCaApi;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.service.base.configuration.cmc.CMCPortConstraints;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
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
  private static final MultiValueMap<String,String> HEADER_MAP;

  private ApplicationEventPublisher applicationEventPublisher;
  private final Map<String, CMCCaApi> cmcCaApiMap;
  private final CMCPortConstraints cmcPortConstraints;

  static {
    HEADER_MAP = new LinkedMultiValueMap<>();
    HEADER_MAP.add("Cache-Control", "no-cache, no-store, must-revalidate");
    HEADER_MAP.add("Pragma", "no-cache");
    HEADER_MAP.add("Expires", "0");
  }


  @Autowired
  public CMCApiController(Map<String, CMCCaApi> cmcCaApiMap, CMCPortConstraints cmcPortConstraints) {
    this.cmcCaApiMap = cmcCaApiMap;
    this.cmcPortConstraints = cmcPortConstraints;
  }

  /**
   * Processing a POST CMC request for an CMC response for a given CA service instance
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

    if (!contentType.equalsIgnoreCase(CMC_MIME_TYPE)){
      log.debug("Received CMC post request for with illegal Content-Type {}", contentType);
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
    if (StringUtils.isBlank(instance) || !cmcCaApiMap.containsKey(instance)){
      log.debug("Received CMC is not supported for specified instance {}", contentType);
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    try {
      final CMCCaApi cmcCaApi = cmcCaApiMap.get(instance);
      final CMCResponse cmcResponse = cmcCaApi.processRequest(requestPayload.getBody());

      return ResponseEntity
        .ok()
        .headers(new HttpHeaders(HEADER_MAP))
        .contentLength(cmcResponse.getCmcResponseBytes().length)
        .contentType(MediaType.parseMediaType(CMC_MIME_TYPE))
        .body(new InputStreamResource(new ByteArrayInputStream(cmcResponse.getCmcResponseBytes())));

    } catch (Exception ex) {
      log.debug("Unable to parse CMC request: {}", ex.getMessage());
      return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
  }

  @Override public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
    this.applicationEventPublisher = applicationEventPublisher;
  }
}
