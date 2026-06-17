/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.config.VelocityEnvConfig;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCDMConstants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialStatusDetail;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialLedgerService;
import io.mosip.certify.credential.Credential;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.utils.CredentialCacheKeyGenerator;
import io.mosip.certify.utils.LedgerUtils;
import io.mosip.certify.vcformatters.VCFormatter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;

import static io.mosip.certify.utils.CredentialUtils.toJsonMap;

@Slf4j
@Component
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class VcApiTemplateIssuanceSupport {

    @Autowired
    private CredentialCacheKeyGenerator credentialCacheKeyGenerator;

    @Autowired
    private VCFormatter vcFormatter;

    @Autowired
    private CredentialFactory credentialFactory;

    @Autowired
    private StatusListCredentialService statusListCredentialService;

    @Autowired
    private CredentialLedgerService credentialLedgerService;

    @Autowired
    private LedgerUtils ledgerUtils;

    @Autowired
    private VelocityEnvConfig velocityEnvConfig;

    @Value("${mosip.certify.data-provider-plugin.did-url}")
    private String didUrl;

    @Value("${mosip.certify.data-provider-plugin.rendering-template-id:}")
    private String renderTemplateId;

    @Value("${mosip.certify.data-provider-plugin.id-field-prefix-uri:}")
    private String idPrefix;

    @Value("${mosip.certify.data-provider-plugin.vc-expiry-duration:P730D}")
    private String defaultExpiryDuration;

    @Value("#{${mosip.certify.issuer.ledger-enabled:true}}")
    private boolean isLedgerEnabled;

    public String resolveTemplateName(String credentialConfigurationId) {
        String templateName = credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(credentialConfigurationId);
        if (StringUtils.isBlank(templateName) || "default-key".equals(templateName)) {
            throw new CertifyException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID,
                    "No template mapping found for credential configuration: " + credentialConfigurationId);
        }
        return templateName;
    }

    public VcApiIssueResult issueFromTemplate(Map<String, Object> credentialSubject, CredentialConfigurationDTO config) {
        if (!VCFormats.LDP_VC.equals(config.getCredentialFormat())) {
            throw new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT,
                    "VC API v1 supports only ldp_vc credential format");
        }

        String templateName = resolveTemplateName(config.getCredentialConfigKeyId());
        JSONObject jsonObject = new JSONObject(credentialSubject);
        if (config.getCredentialTypes() != null) {
            jsonObject.put(Constants.TYPE, config.getCredentialTypes());
        }

        List<String> credentialStatusPurposeList = vcFormatter.getCredentialStatusPurpose(templateName);
        if (credentialStatusPurposeList != null && !credentialStatusPurposeList.isEmpty()
                && config.getContextURLs() != null && config.getContextURLs().contains(VCDM2Constants.URL)) {
            if (!isLedgerEnabled) {
                log.warn("Ledger feature is disabled while revocation is enabled for template {}", templateName);
            }
            statusListCredentialService.addCredentialStatus(jsonObject, credentialStatusPurposeList.getFirst());
        }

        Map<String, Object> templateParams = buildTemplateParams(credentialSubject, templateName, jsonObject);
        Credential cred = credentialFactory.getCredential(VCFormats.LDP_VC)
                .orElseThrow(() -> new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT));

        try {
            Map<String, Object> updatedTemplateParams = toJsonMap(templateParams);
            Map<String, Object> rootContext = new HashMap<>(templateParams);
            updatedTemplateParams.put("rootContext", rootContext);
            updatedTemplateParams.put("envConfigs", velocityEnvConfig.getEnvConfigs());

            String unsignedCredential = cred.createCredential(updatedTemplateParams, templateName);
            validateUnsignedCredential(unsignedCredential);

            ZonedDateTime issuanceTime = ZonedDateTime.now(ZoneOffset.UTC);
            String time = issuanceTime.format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            if (isLedgerEnabled) {
                storeLedger(jsonObject, templateParams, time);
            }

            VCResult<?> result = cred.addProof(unsignedCredential, "",
                    vcFormatter.getProofAlgorithm(templateName),
                    vcFormatter.getAppID(templateName),
                    vcFormatter.getRefID(templateName),
                    vcFormatter.getDidUrl(templateName),
                    vcFormatter.getSignatureCryptoSuite(templateName));

            return new VcApiIssueResult((JsonLDObject) result.getCredential());
        } catch (JSONException e) {
            log.error("VC API credential generation failed: {}", e.getMessage(), e);
            throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR,
                    "Invalid JSON data encountered during credential generation");
        }
    }

    private Map<String, Object> buildTemplateParams(Map<String, Object> credentialSubject, String templateName,
                                                    JSONObject jsonObject) {
        Map<String, Object> templateParams = new HashMap<>();
        templateParams.put(Constants.TEMPLATE_NAME, templateName);
        templateParams.put(Constants.DID_URL, didUrl);
        if (!StringUtils.isEmpty(renderTemplateId)) {
            templateParams.put(Constants.RENDERING_TEMPLATE_ID, renderTemplateId);
        }
        Object holderId = credentialSubject.get("id");
        templateParams.put("_holderId", holderId != null ? holderId.toString() : "");
        templateParams.putAll(jsonObject.toMap());
        if (!StringUtils.isEmpty(idPrefix)) {
            templateParams.put(VCDMConstants.CREDENTIAL_ID, idPrefix + UUID.randomUUID());
        }
        ZonedDateTime zonedDateTime = ZonedDateTime.now(ZoneOffset.UTC);
        String time = zonedDateTime.format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
        Duration duration = parseExpiryDuration();
        String expiryTime = zonedDateTime.plus(duration).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
        templateParams.put(VCDM2Constants.VALID_FROM, time);
        templateParams.put(VCDM2Constants.VALID_UNTIL, expiryTime);
        return templateParams;
    }

    private Duration parseExpiryDuration() {
        try {
            return Duration.parse(defaultExpiryDuration);
        } catch (DateTimeParseException e) {
            log.warn("Incorrect expiry duration format: {}. Using P730D", defaultExpiryDuration);
            return Duration.parse("P730D");
        }
    }

    private void validateUnsignedCredential(String unsignedCredential) {
        JSONObject unsigned = new JSONObject(unsignedCredential);
        if (unsigned.has(VCDMConstants.PROOF)) {
            throw new CertifyException(ErrorConstants.INVALID_REQUEST, "Credential must not include an existing proof");
        }
    }

    private void storeLedger(JSONObject jsonObject, Map<String, Object> templateParams, String time) {
        Map<String, Object> indexedAttributes = ledgerUtils.extractIndexedAttributes(jsonObject);
        String credentialType = LedgerUtils.extractCredentialType(jsonObject);
        String credentialId = null;
        if (templateParams.containsKey(VCDMConstants.CREDENTIAL_ID)) {
            credentialId = templateParams.get(VCDMConstants.CREDENTIAL_ID).toString();
        }
        CredentialStatusDetail credentialStatusDetail = ledgerUtils.extractCredentialStatusDetails(jsonObject);
        LocalDateTime issuanceDate = LocalDateTime.parse(time, DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
        credentialLedgerService.storeLedgerEntry(credentialId, didUrl, credentialType, credentialStatusDetail,
                indexedAttributes, issuanceDate);
        log.info("VC API ledger entry stored for credentialType: {}", credentialType);
    }

    public record VcApiIssueResult(JsonLDObject verifiableCredential) {
    }
}
