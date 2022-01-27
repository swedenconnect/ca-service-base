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

package se.swedenconnect.ca.service.base.configuration.cmc;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * This component enforce configured port restrictions on the admin UI to ensure that the UI is only available in accordance with set
 * policy.
 *
 * This class typically enforces service port only, but may also implement other controls such as IP address whitelisting etc.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Component
@Slf4j
public class CMCPortConstraints {

  private final CMCConfigProperties cmcConfigProperties;

  @Autowired
  public CMCPortConstraints(CMCConfigProperties cmcConfigProperties) {
    this.cmcConfigProperties = cmcConfigProperties;
    final List<Integer> cmcPorts = cmcConfigProperties.getPort();
    if (cmcPorts == null){
      log.info("No CMC port constraints configured. Accepting CMC requests on any port");
    } else {
      log.info("CMC port constraints configured to restrict CMC requests to the ports: {}",
        cmcPorts.stream().map(String::valueOf).collect(Collectors.joining(",")));
    }
  }

  public void validateRequestPort(HttpServletRequest request) throws IOException {
    final List<Integer> cmcPorts = cmcConfigProperties.getPort();
    if (cmcPorts == null) {
      log.trace("No CMC ports constraints configured. Allow any port");
      return;
    }
    int localPort = request.getLocalPort();
    for (int allowedPort : cmcPorts){
      if (localPort == allowedPort){
        log.trace("UI request to enabled port {}", localPort);
        return;
      }
    }
    log.debug("Blocked CMC request access to requested service port {}", localPort);
    throw new IOException("Illegal requested CMC service port" + localPort);
  }

}
