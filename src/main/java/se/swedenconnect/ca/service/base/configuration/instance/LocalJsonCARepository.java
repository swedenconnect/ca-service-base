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

package se.swedenconnect.ca.service.base.configuration.instance;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;
import se.swedenconnect.ca.engine.ca.repository.SortBy;
import se.swedenconnect.ca.engine.ca.repository.impl.SerializableCertificateRecord;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;
import se.swedenconnect.ca.engine.revocation.crl.RevokedCertificate;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Test implementation of a CA repository
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class LocalJsonCARepository implements CARepository, CRLRevocationDataProvider {

  private static final ObjectMapper mapper = new ObjectMapper();
  private final File crlFile;
  private final File certificateRecordsFile;
  private List<SerializableCertificateRecord> issuedCerts;
  private BigInteger crlNumber;
  private boolean criticalError = false;

  public LocalJsonCARepository(File crlFile, File certificateRecordsFile) throws IOException {
    this.crlFile = crlFile;
    this.certificateRecordsFile = certificateRecordsFile;

    // Get issued certs and crlNumber
    if (!certificateRecordsFile.exists()) {
      issuedCerts = new ArrayList<>();
      certificateRecordsFile.getParentFile().mkdirs();
      if (!certificateRecordsFile.getParentFile().exists()) {
        log.error("Unable to create certificate records file directory");
        throw new IOException("Unable to create certificate records file directory");
      }
      // Save the empty issued certs file using the synchronized certificate storage and save function
      addCertificate(null);
      log.info("Created new CA repository");
    }
    // Load current certs to memory
    issuedCerts = mapper.readValue(certificateRecordsFile,
      new TypeReference<List<SerializableCertificateRecord>>() {
    });
    log.info("Local JSON file backed CA repository initialized with {} certificates", issuedCerts.size());
    if (!crlFile.exists()) {
      this.crlNumber = BigInteger.ZERO;
      crlFile.getParentFile().mkdirs();
      if (!crlFile.getParentFile().exists()) {
        log.error("Unable to create crl file directory");
        throw new IOException("Unable to create crl file directory");
      }
      log.info("Starting new CRL sequence with CRL number 0");
    }
    else {
      crlNumber = getCRLNumberFromCRL();
      log.info("CRL number counter initialized with CRL number {}", crlNumber.toString());
    }
  }

  private BigInteger getCRLNumberFromCRL() throws IOException {
    X509CRLHolder crlHolder = new X509CRLHolder(new FileInputStream(crlFile));
    Extension crlNumberExtension = crlHolder.getExtension(Extension.cRLNumber);
    CRLNumber crlNumberFromCrl = CRLNumber.getInstance(crlNumberExtension.getParsedValue());
    return crlNumberFromCrl.getCRLNumber();
  }

  /** {@inheritDoc} */
  @Override public List<BigInteger> getAllCertificates() {
    return issuedCerts.stream()
      .map(certificateRecord -> certificateRecord.getSerialNumber())
      .collect(Collectors.toList());
  }

  /** {@inheritDoc} */
  @Override public CertificateRecord getCertificate(BigInteger bigInteger) {
    Optional<SerializableCertificateRecord> recordOptional = issuedCerts.stream()
      .filter(certificateRecord -> certificateRecord.getSerialNumber().equals(bigInteger))
      .findFirst();
    return recordOptional.isPresent() ? recordOptional.get() : null;
  }

  /** {@inheritDoc} */
  @Override public CRLRevocationDataProvider getCRLRevocationDataProvider() {
    return this;
  }

  /** {@inheritDoc} */
  @Override public int getCertificateCount(boolean notRevoked) {
    if (notRevoked) {
      return (int) issuedCerts.stream()
        .filter(certificateRecord -> !certificateRecord.isRevoked())
        .count();
    }
    return issuedCerts.size();
  }

  /** {@inheritDoc} */
  @Override public List<CertificateRecord> getCertificateRange(int page, int pageSize, boolean notRevoked, SortBy sortBy) {

    List<CertificateRecord> records = issuedCerts.stream()
      .filter(certificateRecord -> {
        if (notRevoked) {
          return !certificateRecord.isRevoked();
        }
        return true;
      })
      .collect(Collectors.toList());

    if (sortBy != null) {
      switch (sortBy) {
      case serialNumber:
        Collections.sort(records, Comparator.comparing(CertificateRecord::getSerialNumber));
        break;
      case issueDate:
        Collections.sort(records, Comparator.comparing(CertificateRecord::getIssueDate));
        break;
      }
    }

    int startIdx = page * pageSize;
    int endIdx = startIdx + pageSize;

    if (startIdx > records.size()){
      return new ArrayList<>();
    }

    if (endIdx > records.size()) {
      endIdx = records.size();
    }

    List<CertificateRecord> resultCertList = new ArrayList<>();
    for (int i = startIdx; i<endIdx;i++) {
      resultCertList.add(records.get(i));
    }

    return resultCertList;
  }

  @Override public List<RevokedCertificate> getRevokedCertificates() {
    return issuedCerts.stream()
      .filter(certificateRecord -> certificateRecord.isRevoked())
      .map(certificateRecord -> new RevokedCertificate(
        certificateRecord.getSerialNumber(),
        certificateRecord.getRevocationTime(),
        certificateRecord.getReason()
      ))
      .collect(Collectors.toList());
  }

  @Override public BigInteger getNextCrlNumber() {
    crlNumber = crlNumber.add(BigInteger.ONE);
    return crlNumber;
  }

  @SneakyThrows @Override public void publishNewCrl(X509CRLHolder crl) {
    FileUtils.writeByteArrayToFile(crlFile, crl.getEncoded());
  }

  @Override public X509CRLHolder getCurrentCrl() {
    try {
      return new X509CRLHolder(new FileInputStream(crlFile));
    }
    catch (Exception e) {
      log.debug("No current CRL is available. Returning null");
      return null;
    }
  }

  /**
   * From this point we only deal with functions that updates the repository
   */


  /** {@inheritDoc} */
  @Override public void addCertificate(X509CertificateHolder certificate) throws IOException {
    try {
      internalRepositoryUpdate(UpdateType.addCert, new Object[]{certificate});
    }
    catch (Exception e) {
      throw e instanceof IOException
        ? (IOException) e
        : new IOException(e);
    }
  }

  private void internalAddCertificate(X509CertificateHolder certificate) throws IOException {
    if (criticalError){
      throw new IOException("This repository encountered a critical error and is not operational - unable to store certificates");
    }
    if (certificate != null) {
      CertificateRecord record = getCertificate(certificate.getSerialNumber());
      if (record != null) {
        throw new IOException("This certificate already exists in the certificate repository");
      }
      issuedCerts.add(new SerializableCertificateRecord(certificate.getEncoded(), certificate.getSerialNumber(),
        certificate.getNotBefore(), certificate.getNotAfter(), false, null, null));
    }
    if (!saveRepositoryData()){
      throw new IOException("Unable to save issued certificate");
    }
  }

  /** {@inheritDoc} */
  @Override public void revokeCertificate(BigInteger serialNumber, int reason, Date revocationTime) throws CertificateRevocationException {
    try {
      internalRepositoryUpdate(UpdateType.revokeCert, new Object[]{serialNumber, reason, revocationTime});
    }
    catch (Exception e) {
      throw e instanceof CertificateRevocationException
        ? (CertificateRevocationException) e
        : new CertificateRevocationException(e);
    }
  }

  private void internalRevokeCertificate(BigInteger serialNumber, int reason, Date revocationTime) throws CertificateRevocationException {
    if (serialNumber == null) {
      throw new CertificateRevocationException("Null Serial number");
    }
    CertificateRecord certificateRecord = getCertificate(serialNumber);
    if (certificateRecord == null) {
      throw new CertificateRevocationException("No such certificate (" + serialNumber.toString(16) + ")");
    }
    certificateRecord.setRevoked(true);
    certificateRecord.setReason(reason);
    certificateRecord.setRevocationTime(revocationTime);
    // Save revoked certificate
    if (!saveRepositoryData()){
      throw new CertificateRevocationException("Unable to save revoked status data");
    }
  }

  /** {@inheritDoc} */
  @Override public List<BigInteger> removeExpiredCerts(int gracePeriodSeconds) throws IOException{
    try {
      return (List<BigInteger>) internalRepositoryUpdate(UpdateType.removeExpiredCerts, new Object[]{gracePeriodSeconds});
    }
    catch (Exception e) {
      throw e instanceof IOException
        ? (IOException) e
        : new IOException(e);
    }
  }

  private List<BigInteger> internalRemoveExpiredCerts(int gracePeriodSeconds) throws IOException {
    List<BigInteger> removedSerialList = new ArrayList<>();
    Date notBefore = new Date(System.currentTimeMillis() - (1000 * gracePeriodSeconds));
    issuedCerts = issuedCerts.stream()
      .filter(certificateRecord -> {
        final Date expiryDate = certificateRecord.getExpiryDate();
        // Check if certificate expired before the current time minus grace period
        if (expiryDate.before(notBefore)){
          // Yes - Remove certificate
          removedSerialList.add(certificateRecord.getSerialNumber());
          return false;
        }
        // No - keep certificate on repository
        return true;
      })
      .collect(Collectors.toList());
    if (!saveRepositoryData()){
      throw new IOException("Unable to save consolidated certificate list");
    }
    return removedSerialList;
  }

  /**
   * All requests to modify the CA repository must go through this function to ensure that all updates are thread safe
   * @param updateType type of repository update
   * @param args input arguments to the update request
   * @return the return object of this update request
   * @throws Exception On errors performing the update request
   */
  private synchronized Object internalRepositoryUpdate(UpdateType updateType, Object[] args) throws Exception {
    switch (updateType){
    case addCert:
      internalAddCertificate((X509CertificateHolder) args[0]);
      return null;
    case revokeCert:
      internalRevokeCertificate((BigInteger) args[0], (int) args[1], (Date) args[2]);
      return null;
    case removeExpiredCerts:
      return internalRemoveExpiredCerts((int) args[0]);
    }
    throw new IOException("Unsupported action");
  }

  private boolean saveRepositoryData(){
    try {
      // Attempt to save repository data
      mapper.writeValue(certificateRecordsFile, issuedCerts);
      return true;
    }
    catch (IOException e) {
      log.error("Error writing to the ca repository storage file", e);
      criticalError = true;
    }
    return false;
  }


  public enum UpdateType {
    //TODO Fill in rest
    addCert, revokeCert, removeExpiredCerts
  }



}
