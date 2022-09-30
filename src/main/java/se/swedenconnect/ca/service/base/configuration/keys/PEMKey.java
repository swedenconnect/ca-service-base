package se.swedenconnect.ca.service.base.configuration.keys;

import lombok.Getter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.springframework.core.io.Resource;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Operations related to a key imported in PEM format where the key may be encrypted under a password.
 */
public class PEMKey {

  /** the private key extracted from provided PEM data */
  @Getter PrivateKey privateKey;

  /**
   * Constructor, extracting any existing private key from a resource
   * @param location the location of the PEM data file
   * @param password password used to decrypt PEM data, if relevant
   * @throws IOException general data encoding errors
   * @throws OperatorCreationException data decryption errors
   * @throws PKCSException error decoding private key from encrypted PEM data
   */
  public PEMKey(final Resource location, final String password) throws IOException, OperatorCreationException, PKCSException {
    final List<Object> pemObjects = getPemObjects(location.getInputStream(), password);
    privateKey = pemObjects.stream()
      .filter(o -> o instanceof KeyPair || o instanceof PrivateKey)
      .map(o -> {
        if (o instanceof KeyPair) {
          return ((KeyPair) o).getPrivate();
        }
        return (PrivateKey) o;
      }).findFirst().orElse(null);
  }

  /**
   * Retrieve a list of PEM objects found in the provided input stream that are of the types PrivateKey (Encrypted or Plaintext), KeyPair or certificate
   * @param is Inputstream with the PEM resources
   * @param password Optional Password for decrypting PKCS8 private key
   * @return A list of objects (PrivateKey, KeyPair or X509CertificateHolder)
   * @throws IOException general data encoding errors
   * @throws OperatorCreationException data decryption errors
   * @throws PKCSException error decoding private key from encrypted PEM data
   */
  public static List<Object> getPemObjects(InputStream is, String password) throws IOException, OperatorCreationException, PKCSException {
    List<Object> pemObjList = new ArrayList<>();
    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
    Reader rdr = new BufferedReader(new InputStreamReader(is));
    PEMParser parser = new PEMParser(rdr);
    Object o;
    while ((o = parser.readObject()) != null) {
      if (o instanceof KeyPair) {
        pemObjList.add(o);
      }
      if (o instanceof PrivateKeyInfo) {
        PrivateKey privateKey = converter.getPrivateKey(PrivateKeyInfo.getInstance(o));
        pemObjList.add(privateKey);
      }
      if (o instanceof PKCS8EncryptedPrivateKeyInfo && password !=null){
        InputDecryptorProvider pkcs8Prov = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(password.toCharArray());
        PrivateKey privateKey = converter.getPrivateKey(((PKCS8EncryptedPrivateKeyInfo) o).decryptPrivateKeyInfo(pkcs8Prov));
        pemObjList.add(privateKey);
      }
      if (o instanceof X509CertificateHolder){
        pemObjList.add(o);
      }
    }
    return pemObjList;
  }

}
