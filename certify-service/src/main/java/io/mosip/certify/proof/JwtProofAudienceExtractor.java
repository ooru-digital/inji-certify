/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.proof;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import io.mosip.certify.core.dto.CredentialProof;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.text.ParseException;
import java.util.List;

/**
 * Reads JWT proof {@code aud} without verifying the signature.
 * Used to resolve the Credential Issuer Identifier before proof validation.
 */
@Slf4j
public final class JwtProofAudienceExtractor {

    private JwtProofAudienceExtractor() {
    }

    public static List<String> extractAudiences(CredentialProof proof) {
        if (proof == null || StringUtils.isBlank(proof.getJwt())) {
            return List.of();
        }
        try {
            JWT jwt = JWTParser.parse(proof.getJwt());
            List<String> audiences = jwt.getJWTClaimsSet().getAudience();
            return audiences == null ? List.of() : List.copyOf(audiences);
        } catch (ParseException e) {
            log.debug("Could not parse JWT proof audiences for issuer resolution");
            return List.of();
        }
    }
}
