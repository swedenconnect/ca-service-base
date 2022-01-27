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

package se.swedenconnect.ca.service.base.configuration.health;

import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ServiceHealthWarningException extends RuntimeException{

  @Getter @Setter private Map<String, Object> details = new HashMap<>();

  public ServiceHealthWarningException() {
  }

  public ServiceHealthWarningException(String message) {
    super(message);
  }

  public ServiceHealthWarningException(String message, Map<String, Object> details) {
    super(message);
    this.details = details;
  }

  public ServiceHealthWarningException(String message, Throwable cause) {
    super(message, cause);
  }

  public ServiceHealthWarningException(Throwable cause) {
    super(cause);
  }

  public ServiceHealthWarningException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

  public void addDetail(String key, Object value){
    details.put(key, value);
  }
}
