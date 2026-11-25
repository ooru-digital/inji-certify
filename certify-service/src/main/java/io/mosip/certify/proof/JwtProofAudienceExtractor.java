/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.proof;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import io.mosip.certify.core.dto.ProofType;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.text.ParseException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads JWT proof {@code aud} without verifying the signature.
 * Used to resolve the Credential Issuer Identifier before proof validation.
 */
@Slf4j
public final class JwtProofAudienceExtractor {

    private JwtProofAudienceExtractor() {
    }

    public static List<String> extractAudiences(Map<ProofType, List<String>> proofs) {
        if (proofs == null) {
            return List.of();
        }
        Set<String> audiences = new LinkedHashSet<>();
        for (List<String> values : proofs.values()) {
            if (values != null) {
                values.forEach(value -> audiences.addAll(extractAudiences(value)));
            }
        }
        return List.copyOf(audiences);
    }

    private static List<String> extractAudiences(String proofJwt) {
        if (StringUtils.isBlank(proofJwt)) {
            return List.of();
        }
        try {
            JWT jwt = JWTParser.parse(proofJwt);
            List<String> audiences = jwt.getJWTClaimsSet().getAudience();
            return audiences == null ? List.of() : List.copyOf(audiences);
        } catch (ParseException e) {
            log.debug("Could not parse JWT proof audiences for issuer resolution");
            return List.of();
        }
    }
}
