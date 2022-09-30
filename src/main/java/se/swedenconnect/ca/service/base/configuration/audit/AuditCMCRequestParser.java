package se.swedenconnect.ca.service.base.configuration.audit;

import org.bouncycastle.cms.CMSSignedData;
import se.swedenconnect.ca.cmc.api.CMCRequestParser;
import se.swedenconnect.ca.cmc.auth.CMCReplayChecker;
import se.swedenconnect.ca.cmc.auth.CMCValidator;

import java.io.IOException;

/**
 * This CMC request parser is a simplified CMC request parser that do not implement replay protection
 * The purpose of this parser is simply to support CMC request parsing to provide information to the audit logger
 */
public class AuditCMCRequestParser extends CMCRequestParser {

  /**
   * Constructor
   * @param validator validator for validating CMC requests
   */
  public AuditCMCRequestParser(CMCValidator validator) {
    super(validator, cmsSignedData -> {});
  }
}
