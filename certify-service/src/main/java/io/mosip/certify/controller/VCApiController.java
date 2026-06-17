/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.certify.core.dto.VcApiIssueRequest;
import io.mosip.certify.core.dto.VcApiIssueResponse;
import io.mosip.certify.services.VCApiIssuanceService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/vc-api")
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class VCApiController {

    @Autowired
    private VCApiIssuanceService vcApiIssuanceService;

    @PostMapping(value = "/credentials/issue", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<VcApiIssueResponse> issueCredential(@Valid @RequestBody VcApiIssueRequest request)
            throws JsonProcessingException {
        log.info("VC API credentials/issue for configuration: {}",
                request.getOptions().getCredentialConfigurationId());
        return ResponseEntity.ok(vcApiIssuanceService.issue(request));
    }
}
