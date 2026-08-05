/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import lombok.Data;

/**
 * Optional W3C VC API issue options (proof hints). Credential configuration id is
 * supplied via {@code X-Credential-Configuration-Id} header, not this object.
 */
@Data
public class VCApiIssueOptions {

    private String type;

    private String verificationMethod;

    private String proofPurpose;

    private String created;

    private String challenge;

    private String domain;
}
