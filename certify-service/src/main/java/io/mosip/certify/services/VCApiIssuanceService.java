/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.VcApiIssueRequest;
import io.mosip.certify.core.dto.VcApiIssueResponse;
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
    private VcApiTemplateIssuanceSupport vcApiTemplateIssuanceSupport;

    public VcApiIssueResponse issue(VcApiIssueRequest request) throws JsonProcessingException {
        String credentialConfigurationId = request.getOptions().getCredentialConfigurationId();
        log.info("VC API issue request for configuration: {}", credentialConfigurationId);

        CredentialConfigurationDTO config = credentialConfigurationService
                .getCredentialConfigurationById(credentialConfigurationId);

        VcApiTemplateIssuanceSupport.VcApiIssueResult result = vcApiTemplateIssuanceSupport
                .issueFromTemplate(request.getCredentialSubject(), config);

        VcApiIssueResponse response = new VcApiIssueResponse();
        response.setVerifiableCredential(toCredentialMap(result.verifiableCredential()));
        return response;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> toCredentialMap(JsonLDObject jsonLDObject) {
        Object json = jsonLDObject.getJsonObject();
        if (json instanceof Map) {
            return new LinkedHashMap<>((Map<String, Object>) json);
        }
        return new LinkedHashMap<>(jsonLDObject.getJsonObject());
    }
}
