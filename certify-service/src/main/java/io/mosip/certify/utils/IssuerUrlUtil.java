/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import io.mosip.certify.core.constants.IssuerConstants;
import org.apache.commons.lang3.StringUtils;

/**
 * Public OID4VCI URLs are built from {@code mosip.certify.domain.url} only.
 * Do not append {@code server.servlet.path} — injistack domain.url already includes {@code /certify}.
 */
public final class IssuerUrlUtil {

    private IssuerUrlUtil() {
    }

    public static String trimTrailingSlash(String url) {
        if (StringUtils.isBlank(url)) {
            return "";
        }
        String trimmed = url.trim();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    /**
     * Unique Credential Issuer Identifier per OpenID4VCI.
     * {@code default} stays at the domain base; other issuers append {@code /{issuerId}}.
     */
    public static String buildCredentialIssuerUrl(String domainUrl, String issuerId) {
        String base = trimTrailingSlash(domainUrl);
        if (StringUtils.isBlank(issuerId) || IssuerConstants.DEFAULT_ISSUER_ID.equals(issuerId)) {
            return base;
        }
        return base + "/" + issuerId;
    }

    public static String buildOpenIdCredentialIssuerWellKnownUrl(String domainUrl, String issuerId) {
        return buildCredentialIssuerUrl(domainUrl, issuerId) + "/.well-known/openid-credential-issuer";
    }

    /**
     * Shared credential endpoint for all issuers. Wallets read this from metadata
     * rather than concatenating it under {@code /{issuerId}}.
     */
    public static String buildCredentialEndpoint(String domainUrl, String version) {
        String base = trimTrailingSlash(domainUrl);
        if (version == null || "latest".equals(version)) {
            return base + "/issuance/credential";
        }
        return base + "/issuance/" + version + "/credential";
    }

    public static String buildNonceEndpoint(String domainUrl) {
        return trimTrailingSlash(domainUrl) + "/nonce";
    }

    /**
     * Last path segment of a Credential Issuer Identifier, e.g.
     * {@code https://host/certify/cr-org} → {@code cr-org}.
     */
    public static String extractLastPathSegment(String url) {
        String trimmed = trimTrailingSlash(url);
        if (trimmed.isEmpty()) {
            return "";
        }
        int lastSlash = trimmed.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash == trimmed.length() - 1) {
            return trimmed;
        }
        return trimmed.substring(lastSlash + 1);
    }
}
