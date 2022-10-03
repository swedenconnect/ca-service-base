/*
 * Copyright 2021-2022 Sweden Connect
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
package se.swedenconnect.ca.service.base.ca;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;
import se.swedenconnect.ca.engine.ca.repository.SortBy;
import se.swedenconnect.ca.engine.ca.repository.impl.SerializableCertificateRecord;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;
import se.swedenconnect.ca.engine.revocation.crl.RevokedCertificate;

/**
 * Test implementation of a CA repository.
 */
@Slf4j
public class LocalJsonCARepository implements CARepository, CRLRevocationDataProvider {

  private static final ObjectMapper mapper = new ObjectMapper();
  private final File crlFile;
  private final File certificateRecordsFile;
  private List<SerializableCertificateRecord> issuedCerts;
  private BigInteger crlNumber;
  private boolean criticalError = false;

  /**
   * Constructor for a local file-based CA repository
   *
   * @param crlFile the file used to store the latest CRL
   * @param certificateRecordsFile the file used to store issued certificates
   * @throws IOException general data parsing errors
   */
  public LocalJsonCARepository(final File crlFile, final File certificateRecordsFile) throws IOException {
    this.crlFile = crlFile;
    this.certificateRecordsFile = certificateRecordsFile;

    // Get issued certs and crlNumber
    if (!certificateRecordsFile.exists()) {
      this.issuedCerts = new ArrayList<>();
      certificateRecordsFile.getParentFile().mkdirs();
      if (!certificateRecordsFile.getParentFile().exists()) {
        log.error("Unable to create certificate records file directory");
        throw new IOException("Unable to create certificate records file directory");
      }
      // Save the empty issued certs file using the synchronized certificate storage and save function
      this.addCertificate(null);
      log.info("Created new CA repository");
    }
    // Load current certs to memory
    this.issuedCerts = mapper.readValue(certificateRecordsFile,
        new TypeReference<List<SerializableCertificateRecord>>() {
        });
    log.info("Local JSON file backed CA repository initialized with {} certificates", this.issuedCerts.size());
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
      this.crlNumber = this.getCRLNumberFromCRL();
      log.info("CRL number counter initialized with CRL number {}", this.crlNumber.toString());
    }
  }

  private BigInteger getCRLNumberFromCRL() throws IOException {
    final X509CRLHolder crlHolder = new X509CRLHolder(new FileInputStream(this.crlFile));
    final Extension crlNumberExtension = crlHolder.getExtension(Extension.cRLNumber);
    final CRLNumber crlNumberFromCrl = CRLNumber.getInstance(crlNumberExtension.getParsedValue());
    return crlNumberFromCrl.getCRLNumber();
  }

  /** {@inheritDoc} */
  @Override
  public List<BigInteger> getAllCertificates() {
    return this.issuedCerts.stream()
        .map(certificateRecord -> certificateRecord.getSerialNumber())
        .collect(Collectors.toList());
  }

  /** {@inheritDoc} */
  @Override
  public CertificateRecord getCertificate(final BigInteger bigInteger) {
    final Optional<SerializableCertificateRecord> recordOptional = this.issuedCerts.stream()
        .filter(certificateRecord -> certificateRecord.getSerialNumber().equals(bigInteger))
        .findFirst();
    return recordOptional.isPresent() ? recordOptional.get() : null;
  }

  /** {@inheritDoc} */
  @Override
  public CRLRevocationDataProvider getCRLRevocationDataProvider() {
    return this;
  }

  /** {@inheritDoc} */
  @Override
  public int getCertificateCount(final boolean notRevoked) {
    if (notRevoked) {
      return (int) this.issuedCerts.stream()
          .filter(certificateRecord -> !certificateRecord.isRevoked())
          .count();
    }
    return this.issuedCerts.size();
  }

  /** {@inheritDoc} */
  @Override
  public List<CertificateRecord> getCertificateRange(int page, final int pageSize, final boolean notRevoked,
      final SortBy sortBy, final boolean descending) {

    final List<CertificateRecord> records = this.issuedCerts.stream()
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
        records.sort(Comparator.comparing(CertificateRecord::getSerialNumber));
        break;
      case issueDate:
        records.sort(Comparator.comparing(CertificateRecord::getIssueDate));
        break;
      }
    }

    if (descending) {
      Collections.reverse(records);
    }

    page = page < 0 ? 0 : page;

    final int startIdx = page * pageSize;
    int endIdx = startIdx + pageSize;

    if (startIdx > records.size()) {
      return new ArrayList<>();
    }

    if (endIdx > records.size()) {
      endIdx = records.size();
    }

    final List<CertificateRecord> resultCertList = new ArrayList<>();
    for (int i = startIdx; i < endIdx; i++) {
      resultCertList.add(records.get(i));
    }

    return resultCertList;
  }

  @Override
  public List<RevokedCertificate> getRevokedCertificates() {
    return this.issuedCerts.stream()
        .filter(certificateRecord -> certificateRecord.isRevoked())
        .map(certificateRecord -> new RevokedCertificate(
            certificateRecord.getSerialNumber(),
            certificateRecord.getRevocationTime(),
            certificateRecord.getReason()))
        .collect(Collectors.toList());
  }

  @Override
  public BigInteger getNextCrlNumber() {
    this.crlNumber = this.crlNumber.add(BigInteger.ONE);
    return this.crlNumber;
  }

  @SneakyThrows
  @Override
  public void publishNewCrl(final X509CRLHolder crl) {
    FileUtils.writeByteArrayToFile(this.crlFile, crl.getEncoded());
  }

  @Override
  public X509CRLHolder getCurrentCrl() {
    try {
      return new X509CRLHolder(new FileInputStream(this.crlFile));
    }
    catch (final Exception e) {
      log.debug("No current CRL is available. Returning null");
      return null;
    }
  }

  /**
   * From this point we only deal with functions that updates the repository
   */

  /** {@inheritDoc} */
  @Override
  public void addCertificate(final X509CertificateHolder certificate) throws IOException {
    try {
      this.internalRepositoryUpdate(UpdateType.addCert, new Object[] { certificate });
    }
    catch (final Exception e) {
      throw e instanceof IOException
          ? (IOException) e
          : new IOException(e);
    }
  }

  private void internalAddCertificate(final X509CertificateHolder certificate) throws IOException {
    if (this.criticalError) {
      throw new IOException(
          "This repository encountered a critical error and is not operational - unable to store certificates");
    }
    if (certificate != null) {
      final CertificateRecord record = this.getCertificate(certificate.getSerialNumber());
      if (record != null) {
        throw new IOException("This certificate already exists in the certificate repository");
      }
      this.issuedCerts.add(new SerializableCertificateRecord(certificate.getEncoded(), certificate.getSerialNumber(),
          certificate.getNotBefore(), certificate.getNotAfter(), false, null, null));
    }
    if (!this.saveRepositoryData()) {
      throw new IOException("Unable to save issued certificate");
    }
  }

  /** {@inheritDoc} */
  @Override
  public void revokeCertificate(final BigInteger serialNumber, final int reason, final Date revocationTime)
      throws CertificateRevocationException {
    try {
      this.internalRepositoryUpdate(UpdateType.revokeCert, new Object[] { serialNumber, reason, revocationTime });
    }
    catch (final Exception e) {
      throw e instanceof CertificateRevocationException
          ? (CertificateRevocationException) e
          : new CertificateRevocationException(e);
    }
  }

  private void internalRevokeCertificate(final BigInteger serialNumber, final int reason, final Date revocationTime)
      throws CertificateRevocationException {
    if (serialNumber == null) {
      throw new CertificateRevocationException("Null Serial number");
    }
    final CertificateRecord certificateRecord = this.getCertificate(serialNumber);
    if (certificateRecord == null) {
      throw new CertificateRevocationException("No such certificate (" + serialNumber.toString(16) + ")");
    }
    if (certificateRecord.isRevoked() && CRLReason.aACompromise < certificateRecord.getReason()) {
      throw new CertificateRevocationException("Illegal reason code");
    }

    if (certificateRecord.isRevoked()) {
      if (certificateRecord.getReason() == CRLReason.certificateHold) {
        if (CRLReason.removeFromCRL == reason) {
          // remove this certificate from certificateHold status
          log.debug("Removing certificate from certificateHold");
          certificateRecord.setRevoked(false);
          certificateRecord.setReason(null);
          certificateRecord.setRevocationTime(null);
          // Save revoked certificate
          if (!this.saveRepositoryData()) {
            throw new CertificateRevocationException("Unable to save revoked status data");
          }
          return;
        }
        // This was not a request to remove the revocation, but to permanently revoke.
        log.debug("Modifying revoked certificate from certificateHold to reason {}", reason);
        certificateRecord.setRevoked(true);
        certificateRecord.setReason(reason);
        certificateRecord.setRevocationTime(revocationTime);
        // Save revoked certificate
        if (!this.saveRepositoryData()) {
          throw new CertificateRevocationException("Unable to save revoked status data");
        }
        return;
      }
      else {
        if (CRLReason.removeFromCRL == reason) {
          log.debug("Revocation removal request denied since certificate has already been permanently revoked");
          throw new CertificateRevocationException(
              "Revocation removal request denied since certificate has already been permanently revoked");
        }
        log.debug("Certificate is already revoked with reason other than certificate hold");
        throw new CertificateRevocationException(
            "Revocation request denied since certificate is already revoked with reason other than certificate hold");
      }
    }

    // This certificate was not revoked before. Revoke it
    if (CRLReason.removeFromCRL == reason) {
      log.debug("Revocation removal request denied since certificate is not on hold");
      throw new CertificateRevocationException("Removal request for a certificate that has not been revoked");
    }

    certificateRecord.setRevoked(true);
    certificateRecord.setReason(reason);
    certificateRecord.setRevocationTime(revocationTime);
    // Save revoked certificate
    if (!this.saveRepositoryData()) {
      throw new CertificateRevocationException("Unable to save revoked status data");
    }
  }

  /** {@inheritDoc} */
  @SuppressWarnings("unchecked")
  @Override
  public List<BigInteger> removeExpiredCerts(final int gracePeriodSeconds) throws IOException {
    try {
      return (List<BigInteger>) this.internalRepositoryUpdate(UpdateType.removeExpiredCerts,
          new Object[] { gracePeriodSeconds });
    }
    catch (final Exception e) {
      throw e instanceof IOException
          ? (IOException) e
          : new IOException(e);
    }
  }

  private List<BigInteger> internalRemoveExpiredCerts(final int gracePeriodSeconds) throws IOException {
    final List<BigInteger> removedSerialList = new ArrayList<>();
    final Date notBefore = new Date(System.currentTimeMillis() - 1000L * gracePeriodSeconds);
    this.issuedCerts = this.issuedCerts.stream()
        .filter(certificateRecord -> {
          final Date expiryDate = certificateRecord.getExpiryDate();
          // Check if certificate expired before the current time minus grace period
          if (expiryDate.before(notBefore)) {
            // Yes - Remove certificate
            removedSerialList.add(certificateRecord.getSerialNumber());
            return false;
          }
          // No - keep certificate on repository
          return true;
        })
        .collect(Collectors.toList());
    if (!this.saveRepositoryData()) {
      throw new IOException("Unable to save consolidated certificate list");
    }
    return removedSerialList;
  }

  /**
   * All requests to modify the CA repository must go through this function to ensure that all updates are thread safe
   *
   * @param updateType type of repository update
   * @param args input arguments to the update request
   * @return the return object of this update request
   * @throws Exception On errors performing the update request
   */
  private synchronized Object internalRepositoryUpdate(final UpdateType updateType, final Object[] args)
      throws Exception {
    switch (updateType) {
    case addCert:
      this.internalAddCertificate((X509CertificateHolder) args[0]);
      return null;
    case revokeCert:
      this.internalRevokeCertificate((BigInteger) args[0], (int) args[1], (Date) args[2]);
      return null;
    case removeExpiredCerts:
      return this.internalRemoveExpiredCerts((int) args[0]);
    }
    throw new IOException("Unsupported action");
  }

  private boolean saveRepositoryData() {
    try {
      // Attempt to save repository data
      mapper.writeValue(this.certificateRecordsFile, this.issuedCerts);
      return true;
    }
    catch (final IOException e) {
      log.error("Error writing to the ca repository storage file", e);
      this.criticalError = true;
    }
    return false;
  }

  /**
   * Enumerations of basic types of repository updates
   */
  public enum UpdateType {
    /** Add a certificate to the repository */
    addCert,
    /** Revoke or un-revoke certificate */
    revokeCert,
    /** Remove expired certificates */
    removeExpiredCerts
  }

}
