package io.mosip.certify.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DidWebUtilTest {

    @Test
    void buildIssuerDidWebIdentifier_usesHostAndIssuerId() {
        String did = DidWebUtil.buildIssuerDidWebIdentifier("https://example.com", "iiitb");
        assertEquals("did:web:example.com:iiitb", did);
    }

    @Test
    void buildIssuerDidWebIdentifier_includesPortWhenPresent() {
        String did = DidWebUtil.buildIssuerDidWebIdentifier("https://example.com:8443", "iiitb");
        assertEquals("did:web:example.com:8443:iiitb", did);
    }

    @Test
    void buildIssuerDidDocumentUrl_isCertifyFetchUrl() {
        String url = DidWebUtil.buildIssuerDidDocumentUrl(
                "https://example.com", "/v1/certify", "iiitb");
        assertEquals("https://example.com/v1/certify/issuers/iiitb/did.json", url);
    }
}
