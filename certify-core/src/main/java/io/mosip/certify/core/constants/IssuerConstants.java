/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.constants;

import java.util.Locale;
import java.util.Set;

public final class IssuerConstants {

    public static final String DEFAULT_ISSUER_ID = "default";
    public static final int ISSUER_ID_MAX_LENGTH = 64;
    public static final String ISSUER_ID_PATTERN =
            "^(?=.*[A-Za-z0-9])[A-Za-z0-9._:-]{1," + ISSUER_ID_MAX_LENGTH + "}$";
    public static final String KEY_APP_ID_PREFIX = "CERTIFY_ISSUER_";
    public static final String IACA_APP_ID_PREFIX = "CERTIFY_IACA_";
    public static final String DS_APP_ID_PREFIX = "CERTIFY_DS_";

    /**
     * First-path segments that must not be used as issuerId so
     * {@code /{issuerId}/.well-known/openid-credential-issuer} cannot collide with existing APIs.
     */
    public static final Set<String> RESERVED_ISSUER_IDS = Set.of(
            DEFAULT_ISSUER_ID,
            "issuance",
            "issuers",
            "oauth",
            "credential-configurations",
            "vc-api",
            "system-info",
            "rendering-template",
            "credentials",
            "ledger-search",
            "nonce"
    );

    private IssuerConstants() {
    }

    public static boolean isReservedIssuerId(String issuerId) {
        return issuerId != null && RESERVED_ISSUER_IDS.contains(issuerId.toLowerCase(Locale.ROOT));
    }
}
