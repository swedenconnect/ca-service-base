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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventEnum;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventFactory;
import se.swedenconnect.ca.service.base.configuration.instance.CAServices;
import se.swedenconnect.ca.service.base.configuration.service.HtmlServiceInfo;

/**
 * This is a sample controller showing principles for audit. This is not meant to be used and only appears in the "mock" profile
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */

@Profile("dev")
@Controller
public class MainController implements ApplicationEventPublisherAware {

  private final HtmlServiceInfo htmlServiceInfo;
  private ApplicationEventPublisher applicationEventPublisher;
  private CAServices caServices;

  @Autowired
  public MainController(CAServices caServices, HtmlServiceInfo htmlServiceInfo) {
    this.caServices = caServices;
    this.htmlServiceInfo = htmlServiceInfo;
  }

  @RequestMapping("/")
  public String mainPage(Model model){
    model.addAttribute("htmlInfo", htmlServiceInfo);
    applicationEventPublisher.publishEvent(AuditEventFactory.getAuditEvent(AuditEventEnum.certificateRequested, "Loading main page"));
    return "main";
  }

  @Override public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
    this.applicationEventPublisher = applicationEventPublisher;
  }
}
