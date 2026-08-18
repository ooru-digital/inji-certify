/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import io.mosip.certify.core.constants.ErrorConstants;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class VCApiIssueRequest {

    /**
     * REQUIRED. VCALM-aligned credential input (claims + optional validity / envelope fields).
     */
    @Valid
    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private VCApiCredentialInput credential;

    /**
     * REQUIRED. Issuance options including credential configuration id.
     */
    @Valid
    @NotNull(message = ErrorConstants.INVALID_REQUEST)
    private VCApiIssueOptions options;
}
