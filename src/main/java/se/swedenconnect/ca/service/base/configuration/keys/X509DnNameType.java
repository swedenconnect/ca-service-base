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

package se.swedenconnect.ca.service.base.configuration.keys;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;

public enum X509DnNameType {
    CN("2.5.4.3"),
    Surename("2.5.4.4"),
    GivenName("2.5.4.42"),
    SerialNumber("2.5.4.5"),
    Org("2.5.4.10"),
    OrgUnit("2.5.4.11"),
    Country("2.5.4.6");

    private static Logger LOG = LoggerFactory.getLogger(X509DnNameType.class);
    private String oidString;

    private X509DnNameType(String oidString) {
        this.oidString = oidString;
    }

    public static X509DnNameType getNameTypeForOid(ASN1ObjectIdentifier oid) {
        String oidString = oid.getId();
        return getNameTypeForOid(oidString);
    }

    private static X509DnNameType getNameTypeForOid(String oidString) {
        X509DnNameType[] types = values();
        X509DnNameType[] var2 = types;
        int var3 = types.length;

        for(int var4 = 0; var4 < var3; ++var4) {
            X509DnNameType type = var2[var4];
            if (type.getOidString().equalsIgnoreCase(oidString)) {
                return type;
            }
        }

        return null;
    }

    public String getOidString() {
        return this.oidString;
    }

    public AttributeTypeAndValue getAttribute(String value) {
        AttributeTypeAndValue atav = new AttributeTypeAndValue(new ASN1ObjectIdentifier(this.oidString), this.getASN1Val(value));
        return atav;
    }

    private ASN1Encodable getASN1Val(String value) {
        boolean isASCII = this.isStringASCII(value);
        if (!isASCII && (this.equals(SerialNumber) || this.equals(Country))) {
            LOG.warn("Illegal characters for name type");
            return null;
        } else {
            Object asn1Val;
            if (!isASCII && !this.equals(SerialNumber) && !this.equals(Country)) {
                asn1Val = new DERUTF8String(value);
            } else {
                asn1Val = new DERPrintableString(value);
            }

            return (ASN1Encodable)asn1Val;
        }
    }

    private boolean isStringASCII(String value) {
        CharsetEncoder asciiEncoder = Charset.forName("US-ASCII").newEncoder();
        return asciiEncoder.canEncode(value);
    }
}
