/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.List;
import java.util.Map;

/**
 * VCALM-aligned unsigned credential input for {@code POST /vc-api/credentials/issue}.
 * <p>
 * {@code credentialSubject}, {@code validFrom}, and {@code validUntil} are used when issuing.
 * {@code @context}, {@code type}, and {@code issuer} are accepted for spec alignment but are
 * rendered from the onboarded {@code vcTemplate} / issuer DID (not from this request).
 */
@Data
public class VCApiCredentialInput {

    /**
     * Optional. Accepted for VCALM shape; not used when signing (comes from vcTemplate).
     */
    @JsonProperty("@context")
    private List<Object> context;

    /**
     * Optional. Accepted for VCALM shape; not used when signing (comes from vcTemplate).
     */
    private List<String> type;

    /**
     * Optional. Accepted for VCALM shape; not used when signing (comes from issuer DID / template).
     * May be a DID string or an issuer object.
     */
    private Object issuer;

    /**
     * Optional credential id. Accepted for VCALM shape; Certify may still generate an id from config.
     */
    private String id;

    /**
     * Optional. Client-supplied validity start (ISO-8601). Used when signing when both
     * {@code validFrom} and {@code validUntil} are present.
     */
    private String validFrom;

    /**
     * Optional. Client-supplied validity end (ISO-8601). Used when signing when both
     * {@code validFrom} and {@code validUntil} are present.
     */
    private String validUntil;

    /**
     * REQUIRED. Claim values matching vcTemplate Velocity placeholders.
     */
    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    @NotEmpty(message = ErrorConstants.INVALID_REQUEST)
    private Map<String, Object> credentialSubject;
}
