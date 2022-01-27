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

package se.swedenconnect.ca.service.base.utils;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import se.swedenconnect.ca.service.base.configuration.keys.BasicX509Utils;

import java.io.*;
import java.security.cert.CertificateEncodingException;
import java.util.*;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class GeneralCAUtils {

  public static X509CertificateHolder getOcspCert(File configFolder, String instance) throws IOException, CertificateEncodingException {
    File certDir = new File(configFolder , "instances/"+ instance+"/certs");
    if (certDir.exists()){
      Optional<File> ocspCertFile = Arrays.stream(certDir.listFiles((dir, name) -> name.endsWith("ocsp.crt"))).findFirst();
      if (ocspCertFile.isPresent()) {
        X509CertificateHolder ocspIssuerCert = new JcaX509CertificateHolder(
          Objects.requireNonNull(
            BasicX509Utils.getCertOrNull(
              FileUtils.readFileToByteArray(ocspCertFile.get()))));
        return ocspIssuerCert;
      }
    }
    return null;
  }

  public static boolean isOCSPCert(X509CertificateHolder cert) {
    try {
      return ExtendedKeyUsage.fromExtensions(cert.getExtensions()).hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning);
    }
    catch (Exception ignored) {
    }
    return false;
  }

  /**
   * Retrieve a list of PEM objects found in the provided input stream that are of the types PrivateKey (Encrypted or Plaintext), KeyPair or certificate
   *
   * @param file the resource file holding certificate data
   * @return list of present certificates
   * @throws IOException on error decoding the data in the specified file
   */
  public static List<X509CertificateHolder> getPEMCertsFromFile(File file) throws IOException {
    List<X509CertificateHolder> pemObjList = new ArrayList<>();
    Reader rdr = new BufferedReader(new FileReader(file));
    PEMParser parser = new PEMParser(rdr);
    Object o;
    while ((o = parser.readObject()) != null) {
      if (o instanceof X509CertificateHolder) {
        pemObjList.add((X509CertificateHolder) o);
      }
    }
    return pemObjList;
  }

  /**
   * Locate the file specified by either an absolute path or a classpath resource
   *
   * @param filename the absolute path of the file name or resource
   * @return the first file in the directory that match the suffix or null if absent
   */
  public static File locateFileOrResource(String filename) {
    if (filename.startsWith("classpath:")){
      return new File(GeneralCAUtils.class.getResource("/" + filename.substring(10)).getFile());
    }
    return new File(filename);
  }


}
