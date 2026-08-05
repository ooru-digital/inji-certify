/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.Map;

@Data
public class VCApiIssueRequest {

    /**
     * REQUIRED. Full unsigned W3C Verifiable Credential (no proof).
     */
    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    @NotEmpty(message = ErrorConstants.INVALID_REQUEST)
    private Map<String, Object> credential;

    /**
     * OPTIONAL. W3C issue options object for request-shape compatibility.
     * Must be omitted or empty; proof hints are not applied in this release.
     * Config id is not taken from options — use {@code X-Credential-Configuration-Id}.
     */
    private VCApiIssueOptions options;
}
