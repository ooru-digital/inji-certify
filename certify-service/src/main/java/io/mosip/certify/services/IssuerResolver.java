package io.mosip.certify.services;

import io.mosip.certify.config.IssuerContext;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.IssuerConstants;
import io.mosip.certify.core.dto.CredentialProof;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.validation.IssuerIdValidator;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.proof.JwtProofAudienceExtractor;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.IssuerRepository;
import io.mosip.certify.utils.IssuerUrlUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
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
     * on {@code POST /issuance/credential}; the JWT proof {@code aud} is the OpenID4VCI
     * Credential Issuer Identifier. Scope is used only when it maps to a single issuer.
     */
    public Issuer resolve(String issuerId, String scopeClaim) {
        return resolve(issuerId, scopeClaim, null);
    }

    public Issuer resolve(String issuerId, String scopeClaim, CredentialProof proof) {
        if (StringUtils.isNotBlank(issuerId)) {
            return resolve(issuerId);
        }
        String matchedIssuerId = findIssuerIdFromProof(proof);
        if (StringUtils.isNotBlank(matchedIssuerId)) {
            log.debug("Resolved issuer {} from JWT proof aud", matchedIssuerId);
            return resolve(matchedIssuerId);
        }
        matchedIssuerId = findIssuerIdByScope(scopeClaim);
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

    private String findIssuerIdFromProof(CredentialProof proof) {
        for (String audience : JwtProofAudienceExtractor.extractAudiences(proof)) {
            if (StringUtils.isBlank(audience)) {
                continue;
            }
            Optional<Issuer> byUrl = findActiveByIssuerUrl(audience.trim());
            if (byUrl.isPresent()) {
                return byUrl.get().getIssuerId();
            }
            String candidate = IssuerUrlUtil.extractLastPathSegment(audience);
            if (IssuerIdValidator.isValid(candidate)) {
                Optional<Issuer> byId = issuerRepository.findByIssuerIdAndStatus(candidate, Constants.ACTIVE);
                if (byId.isPresent()) {
                    return byId.get().getIssuerId();
                }
            }
        }
        return null;
    }

    private Optional<Issuer> findActiveByIssuerUrl(String audience) {
        String trimmed = IssuerUrlUtil.trimTrailingSlash(audience);
        Optional<Issuer> found = findByCredentialIssuerUrl(audience);
        if (found.isEmpty() && !audience.equals(trimmed)) {
            found = findByCredentialIssuerUrl(trimmed);
        }
        if (found.isEmpty() && !trimmed.isEmpty()) {
            found = findByCredentialIssuerUrl(trimmed + "/");
        }
        if (found.isEmpty()) {
            found = findByIdentifier(audience);
        }
        if (found.isEmpty() && !audience.equals(trimmed)) {
            found = findByIdentifier(trimmed);
        }
        if (found.isEmpty() && !trimmed.isEmpty()) {
            found = findByIdentifier(trimmed + "/");
        }
        return found;
    }

    private Optional<Issuer> findByCredentialIssuerUrl(String url) {
        return issuerRepository.findByCredentialIssuerUrlAndStatus(url, Constants.ACTIVE);
    }

    private Optional<Issuer> findByIdentifier(String identifier) {
        return issuerRepository.findByIdentifierAndStatus(identifier, Constants.ACTIVE);
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
            Set<String> issuerIds = new LinkedHashSet<>();
            for (CredentialConfig config : configs) {
                if (StringUtils.isNotBlank(config.getIssuerId())) {
                    issuerIds.add(config.getIssuerId());
                }
            }
            if (issuerIds.size() == 1) {
                return issuerIds.iterator().next();
            }
            log.debug("Scope {} matches {} issuers; not using scope to pick issuer", trimmed, issuerIds.size());
        }
        return null;
    }
}
