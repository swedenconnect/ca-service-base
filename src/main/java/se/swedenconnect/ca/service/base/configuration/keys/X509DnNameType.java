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

package se.swedenconnect.ca.service.base.configuration.keys;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;

import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Enumeration of X.509 certificate distinguished name attributes.
 */
@AllArgsConstructor
@Getter
@Slf4j
public enum X509DnNameType {

    /** Common name attribute */
    CN("2.5.4.3"),
    /** Surname attribute */
    Surename("2.5.4.4"),
    /** Given name attribute */
    GivenName("2.5.4.42"),
    /** Serial number attribute */
    SerialNumber("2.5.4.5"),
    /** Organization name attribute */
    Org("2.5.4.10"),
    /** Organization unit name attribute */
    OrgUnit("2.5.4.11"),
    /** Country name attribute */
    Country("2.5.4.6");

    private final String oidString;

    /**
     * Get the enumeration value for attribute oid
     *
     * @param oid attribute OID
     * @return attribute enumeration or null if the requested OID is not supported
     */
    public static X509DnNameType getNameTypeForOid(ASN1ObjectIdentifier oid) {
        String oidString = oid.getId();
        return getNameTypeForOid(oidString);
    }

    private static X509DnNameType getNameTypeForOid(String oidString) {
        X509DnNameType[] types = values();
        int var3 = types.length;

        for (X509DnNameType type : types) {
            if (type.getOidString().equalsIgnoreCase(oidString)) {
                return type;
            }
        }

        return null;
    }

    /**
     * Get the attribute type and value for this attribute type
     * @param value attribute value
     * @return attribute type and value
     */
    public AttributeTypeAndValue getAttribute(String value) {
        return new AttributeTypeAndValue(new ASN1ObjectIdentifier(this.oidString), this.getASN1Val(value));
    }

    private ASN1Encodable getASN1Val(String value) {
        boolean isASCII = this.isStringASCII(value);
        if (!isASCII && (this.equals(SerialNumber) || this.equals(Country))) {
            log.debug("Illegal characters for name type");
            return null;
        } else {
            ASN1Encodable asn1Val;
            if (!isASCII && !this.equals(SerialNumber) && !this.equals(Country)) {
                asn1Val = new DERUTF8String(value);
            } else {
                asn1Val = new DERPrintableString(value);
            }

            return asn1Val;
        }
    }

    private boolean isStringASCII(String value) {
        CharsetEncoder asciiEncoder = StandardCharsets.US_ASCII.newEncoder();
        return asciiEncoder.canEncode(value);
    }
}
