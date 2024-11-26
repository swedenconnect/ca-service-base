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
package se.swedenconnect.ca.service.base.configuration.keys;

import java.security.PublicKey;

/**
 * Interface for validating a public key.
 */
public interface PublicKeyValidator {

  /**
   * Evaluate a public key to determine that it meets the defined security policy.
   *
   * @param publicKey public key to validate
   * @throws PublicKeyPolicyException if the public key is not valid
   */
  void validatePublicKey(final PublicKey publicKey) throws PublicKeyPolicyException;

}
