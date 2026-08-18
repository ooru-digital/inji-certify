package io.mosip.certify.core.dto;

import lombok.Data;

/**
 * Optional W3C VC API issue options. Accepted only when empty (or omitted on the request)
 * for schema compatibility. Non-blank proof hints are rejected until signing applies them.
 * Credential configuration id is supplied via {@code X-Credential-Configuration-Id}, not here.
 */
@Data
public class VCApiIssueOptions {

    /** Unsupported until signing applies proof type hints. */
    private String type;

    /** Unsupported until signing applies verificationMethod overrides. */
    private String verificationMethod;

    /** Unsupported until signing applies proofPurpose overrides. */
    private String proofPurpose;

    /** Unsupported until signing applies created overrides. */
    private String created;

    /** Unsupported until signing embeds challenge in the proof. */
    private String challenge;

    /** Unsupported until signing embeds domain in the proof. */
    private String domain;
}
