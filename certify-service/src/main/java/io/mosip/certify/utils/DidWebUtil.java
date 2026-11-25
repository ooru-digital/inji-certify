/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import org.apache.commons.lang3.StringUtils;

import java.net.URI;

public final class DidWebUtil {

    private DidWebUtil() {
    }

    /**
     * Builds a did:web identifier of the form {@code did:web:{host[:port]}:{issuerId}}.
     * Clients typically construct and pass this as onboard {@code didUrl}; Certify does not
     * auto-derive it from {@code mosip.certify.domain.url}.
     */
    public static String buildIssuerDidWebIdentifier(String domainUrl, String issuerId) {
        return "did:web:" + extractHostWithPort(domainUrl) + ":" + issuerId;
    }

    /**
     * Certify API URL where clients can fetch the issuer DID document JSON
     * ({@code {domain}{servletPath}/issuers/{issuerId}/did.json}).
     */
    public static String buildIssuerDidDocumentUrl(String domainUrl, String servletPath, String issuerId) {
        String normalizedServletPath = normalizeServletPath(servletPath);
        return domainUrl + normalizedServletPath + "/issuers/" + issuerId + "/did.json";
    }

    private static String extractHostWithPort(String domainUrl) {
        URI uri = URI.create(domainUrl);
        String host = uri.getHost();
        if (host == null) {
            host = domainUrl.replace("https://", "").replace("http://", "");
            int slash = host.indexOf('/');
            if (slash >= 0) {
                host = host.substring(0, slash);
            }
        }
        int port = uri.getPort();
        return port > 0 ? host + ":" + port : host;
    }

    private static String normalizeServletPath(String servletPath) {
        if (StringUtils.isBlank(servletPath) || "/".equals(servletPath)) {
            return "";
        }
        return servletPath.startsWith("/") ? servletPath : "/" + servletPath;
    }
}
