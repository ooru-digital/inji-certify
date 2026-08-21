package io.mosip.certify.utils;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class IssuerUrlUtilTest {

    @Test
    public void buildCredentialIssuerUrl_defaultStaysAtDomain() {
        assertEquals("https://host/certify",
                IssuerUrlUtil.buildCredentialIssuerUrl("https://host/certify/", "default"));
        assertEquals("https://host/certify",
                IssuerUrlUtil.buildCredentialIssuerUrl("https://host/certify", null));
    }

    @Test
    public void buildCredentialIssuerUrl_appendsIssuerId() {
        assertEquals("https://host/certify/iiitb-ac",
                IssuerUrlUtil.buildCredentialIssuerUrl("https://host/certify/", "iiitb-ac"));
    }

    @Test
    public void buildOpenIdCredentialIssuerWellKnownUrl_appendsWellKnown() {
        assertEquals("https://host/certify/iiitb-ac/.well-known/openid-credential-issuer",
                IssuerUrlUtil.buildOpenIdCredentialIssuerWellKnownUrl("https://host/certify", "iiitb-ac"));
        assertEquals("https://host/certify/.well-known/openid-credential-issuer",
                IssuerUrlUtil.buildOpenIdCredentialIssuerWellKnownUrl("https://host/certify", "default"));
    }

    @Test
    public void buildCredentialEndpoint_isSharedAndNotUnderIssuerId() {
        assertEquals("https://host/certify/issuance/credential",
                IssuerUrlUtil.buildCredentialEndpoint("https://host/certify/", "latest"));
        assertEquals("https://host/certify/issuance/vd12/credential",
                IssuerUrlUtil.buildCredentialEndpoint("https://host/certify", "vd12"));
    }
}
