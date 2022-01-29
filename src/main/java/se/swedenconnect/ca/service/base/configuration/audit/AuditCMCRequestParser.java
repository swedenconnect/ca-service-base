package se.swedenconnect.ca.service.base.configuration.audit;

import org.bouncycastle.cms.CMSSignedData;
import se.swedenconnect.ca.cmc.api.CMCRequestParser;
import se.swedenconnect.ca.cmc.auth.CMCReplayChecker;
import se.swedenconnect.ca.cmc.auth.CMCValidator;

import java.io.IOException;

/**
 * Description this CMC request parser is a simplified CMC request parser that do not implement replay protection
 * The purpose of this parser is simply to support CMC request parsing to provide information to the audit logger
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AuditCMCRequestParser extends CMCRequestParser {

  public AuditCMCRequestParser(CMCValidator validator) {
    super(validator, cmsSignedData -> {});
  }
}
