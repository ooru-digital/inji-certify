/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.VCApiIssueRequest;
import io.mosip.certify.core.dto.VCApiIssueResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class VCApiIssuanceService {

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @Autowired
    private VCApiCredentialIssuanceSupport vcApiCredentialIssuanceSupport;

    public VCApiIssueResponse issue(VCApiIssueRequest request, String credentialConfigurationId) {
        log.info("VC API issue request for configuration: {}", credentialConfigurationId);

        try {
            CredentialConfigurationDTO config = credentialConfigurationService
                    .getCredentialConfigurationById(credentialConfigurationId);

            VCApiCredentialIssuanceSupport.VCApiIssueResult result = vcApiCredentialIssuanceSupport
                    .issueValidatedCredential(request.getCredential(), config);

            VCApiIssueResponse response = new VCApiIssueResponse();
            response.setVerifiableCredential(toCredentialMap(result.verifiableCredential()));
            return response;
        } catch (JsonProcessingException e) {
            log.error("VC API issue request failed during configuration lookup: {}", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR,
                    "Invalid JSON data encountered during credential issuance");
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> toCredentialMap(JsonLDObject jsonLDObject) {
        Object json = jsonLDObject.getJsonObject();
        if (json instanceof Map<?, ?> map) {
            return new LinkedHashMap<>((Map<String, Object>) map);
        }
        throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR,
                "Unable to convert verifiable credential to response format");
    }
}
