/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.proof;

import io.mosip.certify.core.dto.CredentialProof;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class JwtProofAudienceExtractorTest {

    @Test
    public void extractAudiences_readsAudWithoutSignature() {
        List<String> audiences = JwtProofAudienceExtractor.extractAudiences(
                jwtProof("{\"aud\":\"https://host/certify/cr-org\"}"));

        assertEquals(List.of("https://host/certify/cr-org"), audiences);
    }

    @Test
    public void extractAudiences_blankOrInvalid_returnsEmpty() {
        assertTrue(JwtProofAudienceExtractor.extractAudiences(null).isEmpty());
        CredentialProof empty = new CredentialProof();
        assertTrue(JwtProofAudienceExtractor.extractAudiences(empty).isEmpty());
        CredentialProof invalid = new CredentialProof();
        invalid.setJwt("not-a-jwt");
        assertTrue(JwtProofAudienceExtractor.extractAudiences(invalid).isEmpty());
    }

    private static CredentialProof jwtProof(String payloadJson) {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        CredentialProof proof = new CredentialProof();
        proof.setJwt(header + "." + payload + ".");
        return proof;
    }
}
