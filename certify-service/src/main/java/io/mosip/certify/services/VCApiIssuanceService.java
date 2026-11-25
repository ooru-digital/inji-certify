/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.VCApiCredentialInput;
import io.mosip.certify.core.dto.VCApiIssueRequest;
import io.mosip.certify.core.dto.VCApiIssueResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.utils.VcApiValidityResolver;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class VCApiIssuanceService {

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @Autowired
    private VCApiTemplateIssuanceSupport vcApiTemplateIssuanceSupport;

    @Autowired
    private VcApiValidityResolver vcApiValidityResolver;

    public VCApiIssueResponse issue(VCApiIssueRequest request) {
        String credentialConfigurationId = request.getOptions().getCredentialConfigurationId();
        log.info("VC API issue request for configuration: {}", credentialConfigurationId);

        try {
            CredentialConfigurationDTO config = credentialConfigurationService
                    .getCredentialConfigurationById(credentialConfigurationId);

            VCApiCredentialInput credential = request.getCredential();
            // @context, type, and issuer on credential are accepted for VCALM shape only;
            // signing still uses onboarded vcTemplate + issuer DID.
            VcApiValidityResolver.ValidityWindow validity = vcApiValidityResolver.resolve(
                    credential.getValidFrom(), credential.getValidUntil());

            VCApiTemplateIssuanceSupport.VCApiIssueResult result = vcApiTemplateIssuanceSupport
                    .issueFromTemplate(credential.getCredentialSubject(), config, validity);

            VCApiIssueResponse response = new VCApiIssueResponse();
            response.setFormat(result.format());
            response.setVerifiableCredential(toResponseCredential(result));
            return response;
        } catch (JsonProcessingException e) {
            log.error("VC API issue request failed during configuration lookup: {}", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR,
                    "Invalid JSON data encountered during credential issuance");
        }
    }

    private Object toResponseCredential(VCApiTemplateIssuanceSupport.VCApiIssueResult result) {
        if (VCFormats.MSO_MDOC.equals(result.format())) {
            if (result.credential() instanceof String credential) {
                return credential;
            }
            throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR,
                    "Unable to convert mso_mdoc credential to response format");
        }
        return toCredentialMap(result.credential());
    }

    /**
     * Property order matching previously issued (wallet-accepted) LDP VCs.
     * Remaining properties are appended in their original encounter order.
     */
    private static final List<String> VC_PROPERTY_ORDER = List.of(
            "id",
            "type",
            "proof",
            "issuer",
            "@context",
            "validFrom",
            "validUntil",
            "issuanceDate",
            "expirationDate",
            "credentialStatus",
            "credentialSubject",
            "credentialSchema",
            "evidence",
            "termsOfUse",
            "refreshService",
            "renderMethod"
    );

    private static final List<String> CREDENTIAL_STATUS_ORDER = List.of(
            "id",
            "type",
            "statusPurpose",
            "statusListIndex",
            "statusListCredential"
    );

    private static final List<String> PROOF_ORDER = List.of(
            "type",
            "created",
            "proofValue",
            "proofPurpose",
            "verificationMethod",
            "cryptosuite",
            "jws",
            "nonce",
            "expires",
            "domain",
            "challenge"
    );

    @SuppressWarnings("unchecked")
    private Map<String, Object> toCredentialMap(Object credential) {
        if (credential instanceof JsonLDObject jsonLDObject) {
            Object json = jsonLDObject.getJsonObject();
            if (json instanceof Map<?, ?> map) {
                return orderIssuedCredential((Map<String, Object>) map);
            }
        }
        if (credential instanceof Map<?, ?> map) {
            return orderIssuedCredential((Map<String, Object>) map);
        }
        throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR,
                "Unable to convert verifiable credential to response format");
    }

    private Map<String, Object> orderIssuedCredential(Map<String, Object> source) {
        Map<String, Object> ordered = orderProperties(source, VC_PROPERTY_ORDER);
        ordered.computeIfPresent("proof", (key, value) -> orderNested(value, PROOF_ORDER));
        ordered.computeIfPresent("credentialStatus", (key, value) -> orderNested(value, CREDENTIAL_STATUS_ORDER));
        ordered.computeIfPresent("credentialSubject", (key, value) -> orderCredentialSubject(value));
        return ordered;
    }

    private Object orderNested(Object value, List<String> preferredOrder) {
        if (value instanceof Map<?, ?> map) {
            return orderProperties(castMap(map), preferredOrder);
        }
        if (value instanceof List<?> list) {
            return list.stream().map(item -> orderNested(item, preferredOrder)).toList();
        }
        return value;
    }

    private Object orderCredentialSubject(Object value) {
        if (!(value instanceof Map<?, ?> map)) {
            return value;
        }
        return orderProperties(castMap(map), List.of("id"));
    }

    private Map<String, Object> orderProperties(Map<String, Object> source, List<String> preferredOrder) {
        Map<String, Object> ordered = new LinkedHashMap<>();
        for (String key : preferredOrder) {
            if (source.containsKey(key)) {
                ordered.put(key, source.get(key));
            }
        }
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            ordered.putIfAbsent(entry.getKey(), entry.getValue());
        }
        return ordered;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> castMap(Map<?, ?> map) {
        return (Map<String, Object>) map;
    }
}
