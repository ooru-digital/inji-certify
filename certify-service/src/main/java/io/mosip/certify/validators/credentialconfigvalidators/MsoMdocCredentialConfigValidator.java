package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.IssuerConstants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import org.apache.commons.lang3.StringUtils;

import java.util.Optional;

public class MsoMdocCredentialConfigValidator {

    /**
     * An mdoc's issuerAuth is signed with signatureAlgo alone, so that is mandatory in DataProvider mode,
     * where Certify signs the credential. In VCIssuance mode the plugin signs it, so signatureAlgo is
     * optional. signatureCryptoSuite plays no part in signing an mdoc: it is optional, its value is not
     * validated, and it is not stored.
     */
    public static boolean isValidCheck(CredentialConfigurationDTO credentialConfig, String pluginMode) {
        return credentialConfig.getDocType() != null && !credentialConfig.getDocType().isEmpty()
                && (!"DataProvider".equals(pluginMode) || (credentialConfig.getSignatureAlgo() != null && !credentialConfig.getSignatureAlgo().isEmpty()))
                && (credentialConfig.getCredentialTypes() == null || credentialConfig.getCredentialTypes().isEmpty()) && (credentialConfig.getContextURLs() == null || credentialConfig.getContextURLs().isEmpty())
                && credentialConfig.getSdJwtVct() == null && credentialConfig.getClaims() == null
                && credentialConfig.getSdJwtClaims() == null;
    }

    public static boolean isConfigAlreadyPresent(CredentialConfigurationDTO credentialConfig,
                                                 CredentialConfigRepository credentialConfigRepository) {
        String issuerId = StringUtils.defaultIfBlank(credentialConfig.getIssuerId(), IssuerConstants.DEFAULT_ISSUER_ID);
        Optional<CredentialConfig> optional =
                credentialConfigRepository.findByIssuerIdAndCredentialFormatAndDocType(
                        issuerId,
                        credentialConfig.getCredentialFormat(),
                        credentialConfig.getDocType());

        return optional.isPresent();
    }
}