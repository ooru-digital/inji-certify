package io.mosip.certify.services;

import io.mosip.certify.config.IssuerContext;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.IssuerConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.validation.IssuerIdValidator;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.IssuerRepository;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

@Slf4j
@Component
public class IssuerResolver {

    private static final Set<String> OIDC_SCOPES = Set.of(
            "openid", "profile", "email", "phone", "address", "offline_access");

    @Autowired
    private IssuerRepository issuerRepository;

    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

    @Autowired
    private IssuerContext issuerContext;

    /**
     * Resolves the issuer for a credential request. Wallets do not send {@code issuerId}
     * on {@code POST /issuance/credential}; when it is absent, match the access-token
     * scope to an active credential configuration.
     */
    public Issuer resolve(String issuerId, String scopeClaim) {
        if (StringUtils.isNotBlank(issuerId)) {
            return resolve(issuerId);
        }
        String matchedIssuerId = findIssuerIdByScope(scopeClaim);
        if (StringUtils.isNotBlank(matchedIssuerId)) {
            log.debug("Resolved issuer {} from access-token scope", matchedIssuerId);
            return resolve(matchedIssuerId);
        }
        return resolve(IssuerConstants.DEFAULT_ISSUER_ID);
    }

    public Issuer resolve(String issuerId) {
        String resolvedId = IssuerIdValidator.normalize(
                StringUtils.defaultIfBlank(issuerId, IssuerConstants.DEFAULT_ISSUER_ID));
        if (!IssuerIdValidator.isValid(resolvedId)) {
            throw new CertifyException(ErrorConstants.INVALID_ISSUER_ID,
                    "Invalid issuerId format: " + resolvedId);
        }

        Issuer issuer = issuerRepository.findById(resolvedId)
                .orElseThrow(() -> new CertifyException(ErrorConstants.ISSUER_NOT_FOUND,
                        "Issuer not found: " + resolvedId));

        if (!Constants.ACTIVE.equals(issuer.getStatus())) {
            throw new CertifyException(ErrorConstants.ISSUER_INACTIVE,
                    "Issuer is inactive: " + resolvedId);
        }

        issuerContext.setCurrent(issuer);
        return issuer;
    }

    public String resolveIssuerId(String issuerId) {
        return StringUtils.defaultIfBlank(issuerId, IssuerConstants.DEFAULT_ISSUER_ID);
    }

    private String findIssuerIdByScope(String scopeClaim) {
        if (StringUtils.isBlank(scopeClaim)) {
            return null;
        }
        for (String scope : scopeClaim.split(Constants.SPACE)) {
            String trimmed = scope.trim();
            if (trimmed.isEmpty() || OIDC_SCOPES.contains(trimmed)) {
                continue;
            }
            List<CredentialConfig> configs = credentialConfigRepository.findByScopeAndStatus(trimmed, Constants.ACTIVE);
            if (configs.isEmpty()) {
                continue;
            }
            if (configs.size() == 1) {
                return configs.get(0).getIssuerId();
            }
            return configs.stream()
                    .map(CredentialConfig::getIssuerId)
                    .filter(id -> !IssuerConstants.DEFAULT_ISSUER_ID.equals(id))
                    .findFirst()
                    .orElse(configs.get(0).getIssuerId());
        }
        return null;
    }
}
