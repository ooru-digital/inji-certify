package io.mosip.certify.services;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.IssuerConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.CredentialConfigException;
import io.mosip.certify.core.exception.CredentialConfigValidationException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.entity.attributes.Claims;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.IssuerRepository;
import io.mosip.certify.utils.CredentialConfigMapper;
import io.mosip.certify.utils.CredentialConfigMetadataResolver;
import io.mosip.certify.utils.IssuerUrlUtil;
import io.mosip.certify.validators.credentialconfigvalidators.CredentialConfigMetadataValidator;
import io.mosip.certify.validators.credentialconfigvalidators.LdpVcCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.MsoMdocCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.QrSettingsValidator;
import io.mosip.certify.validators.credentialconfigvalidators.SdJwtCredentialConfigValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import java.util.*;
import java.util.stream.Collectors;
import com.nimbusds.jose.JWSAlgorithm;
import com.authlete.cose.constants.COSEAlgorithms;

@Slf4j
@Component
@Transactional
public class CredentialConfigurationServiceImpl implements CredentialConfigurationService {

    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

    @Autowired
    private CredentialConfigMapper credentialConfigMapper;

    @Autowired
    private IssuerResolver issuerResolver;

    @Autowired
    private IssuerRepository issuerRepository;

    @Value("${mosip.certify.domain.url}")
    private String credentialIssuer;

    @Value("${mosip.certify.allow-c-nonce:false}")
    private boolean allowCNonce;

    @Value("${mosip.certify.authorization.url}")
    private String authUrl;

    @Value("${server.servlet.path}")
    private String servletPath;

    @Value("${mosip.certify.plugin-mode}")
    private String pluginMode;

    @Value("#{${mosip.certify.credential-config.issuer.display}}")
    private List<Map<String, Object>> issuerDisplay;

    @Value("#{${mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes:{}}}")
    private List<String> allowedCredentialStatusPurposes;

    @Value("#{${mosip.certify.credential-config.cryptographic-binding-methods-supported}}")
    private LinkedHashMap<String, List<String>> cryptographicBindingMethodsSupportedMap;

    @Value("#{${mosip.certify.credential-config.credential-signing-alg-values-supported}}")
    private LinkedHashMap<String, List<String>> credentialSigningAlgValuesSupportedMap;

    @Value("#{${mosip.certify.credential-config.proof-types-supported}}")
    private LinkedHashMap<String, Object> proofTypesSupported;

    @Value("#{${mosip.certify.signature-algo.key-alias-mapper}}")
    private Map<String, List<List<String>>> keyAliasMapper;

    @Value("#{${mosip.certify.credential-config.as-mapping:{}}}")
    private Map<String, String> authorizationServerMapping;

    /** Comma-separated formats advertised on the well-known endpoint. Empty advertises every active configuration. */
    @Value("${mosip.certify.credential-config.wellknown.supported-formats:ldp_vc}")
    private String wellKnownSupportedFormats;

    private static final String CREDENTIAL_CONFIG_CACHE_NAME = "credentialConfig";

    // The algorithms an mso_mdoc issuer may sign with. Only ES256 is supported, as HAIP requires for
    // an mdoc's issuerAuth; RS256 and ES256K are outside ISO 18013-5 altogether.
    private static final Map<String, Integer> COSE_ALGORITHM_INTEGER_MAP = Map.of(
        JWSAlgorithm.ES256.getName(), COSEAlgorithms.ES256
    );

    @Override
    public CredentialConfigResponse addCredentialConfiguration(CredentialConfigurationDTO credentialConfigurationDTO) {
        Issuer issuer = issuerResolver.resolve(issuerResolver.resolveIssuerId(credentialConfigurationDTO.getIssuerId()));
        credentialConfigurationDTO.setIssuerId(issuer.getIssuerId());
        applyIssuerSigningKeys(credentialConfigurationDTO, issuer);
        validateIssuerCredentialBinding(credentialConfigurationDTO, issuer);

        validateCredentialConfiguration(credentialConfigurationDTO, true);

        CredentialConfig credentialConfig = credentialConfigMapper.toEntity(credentialConfigurationDTO);
        credentialConfig.setIssuerId(issuer.getIssuerId());
        if (!StringUtils.hasText(credentialConfig.getDidUrl())) {
            credentialConfig.setDidUrl(issuer.getDidUrl());
        }
        validateAndApplyCredentialConfigMetadataAttributes(credentialConfigurationDTO, credentialConfig);
        return saveCredentialConfiguration(credentialConfig);
    }

    private CredentialConfigResponse saveCredentialConfiguration(CredentialConfig credentialConfig) {
        credentialConfig.setConfigId(UUID.randomUUID().toString());
        credentialConfig.setStatus(Constants.ACTIVE);

        CredentialConfig savedConfig = credentialConfigRepository.save(credentialConfig);
        log.info("Added credential configuration: {}", savedConfig.getConfigId());

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(savedConfig.getCredentialConfigKeyId());
        credentialConfigResponse.setStatus(savedConfig.getStatus());
        credentialConfigResponse.setIssuerId(savedConfig.getIssuerId());

        return credentialConfigResponse;
    }

    private void validateCredentialConfiguration(CredentialConfigurationDTO credentialConfig, boolean shouldCheckDuplicate) {

        validateCommonCredentialConfig(credentialConfig.getCredentialStatusPurposes(),credentialConfig.getVcTemplate(),credentialConfig.getQrSettings(),credentialConfig.getQrSignatureAlgo());

        switch (credentialConfig.getCredentialFormat()) {
            case VCFormats.LDP_VC:
                if (!LdpVcCredentialConfigValidator.isValidCheck(credentialConfig, pluginMode)) {
                    throw new CertifyException(ErrorConstants.LDP_VC_MANDATORY_FIELDS_MISSING, "Fields context, credentialType, signatureCryptoSuite and signatureAlgo (DataProvider plugin mode only) are mandatory for the ldp_vc format.");
                }
                if(shouldCheckDuplicate && LdpVcCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException(ErrorConstants.LDP_VC_CONFIG_EXISTS, "Configuration already exists for the specified context and credentialType.");
                }
                validateKeyAliasMapperConfiguration(credentialConfig);
                break;
            case VCFormats.MSO_MDOC:
                if (!MsoMdocCredentialConfigValidator.isValidCheck(credentialConfig, pluginMode)) {
                    throw new CertifyException(ErrorConstants.MSO_MDOC_MANDATORY_FIELDS_MISSING, "Fields doctype and signatureAlgo (DataProvider plugin mode only) are mandatory for the mso_mdoc format.");
                }
                if(shouldCheckDuplicate && MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException(ErrorConstants.MSO_MDOC_CONFIG_EXISTS, "Configuration already exists for the specified doctype.");
                }
                break;
            case VCFormats.DC_SD_JWT:
                if (!SdJwtCredentialConfigValidator.isValidCheck(credentialConfig, pluginMode)) {
                    throw new CertifyException(ErrorConstants.DC_SD_JWT_MANDATORY_FIELDS_MISSING, "Fields vct and signatureAlgo (DataProvider plugin mode only) are mandatory for the dc+sd-jwt format.");
                }
                if(shouldCheckDuplicate && SdJwtCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException(ErrorConstants.DC_SD_JWT_CONFIG_EXISTS, "Configuration already exists for the specified vct.");
                }
                break;
            default:
                throw new CertifyException(ErrorConstants.UNSUPPORTED_FORMAT, "Unsupported credential format: " + credentialConfig.getCredentialFormat());
        }
    }

    private void validateCommonCredentialConfig(
            List<String> credentialStatusPurposes,
            String vcTemplate,
            List<Map<String, Object>> qrSettings,
            String qrSignatureAlgo){
        if (credentialStatusPurposes != null && credentialStatusPurposes.size() > 1){
            throw new CertifyException(ErrorConstants.MULTIPLE_STATUS_PURPOSES_NOT_SUPPORTED, "Multiple credential status purposes are not supported. Please specify only one.");
        }

        if (credentialStatusPurposes != null && !credentialStatusPurposes.isEmpty() && !allowedCredentialStatusPurposes.contains(credentialStatusPurposes.getFirst())) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_PURPOSE, "Invalid credential status purpose. Allowed values are: " + allowedCredentialStatusPurposes);
        }

        if(pluginMode.equals("DataProvider") && (vcTemplate == null || vcTemplate.isEmpty())) {
            throw new CertifyException(ErrorConstants.CREDENTIAL_TEMPLATE_REQUIRED, "A Credential Template is required for issuers using the Data Provider plugin.");
        }

        if(qrSettings == null || qrSettings.isEmpty()) {
            if(qrSignatureAlgo != null) {
                throw new CertifyException(ErrorConstants.QR_SIGNATURE_ALGO_NOT_ALLOWED, "QR signature algorithm is not allowed when QR settings are not set.");

            }
        } else {
            if (qrSignatureAlgo != null && !qrSignatureAlgo.isEmpty() && !keyAliasMapper.containsKey(qrSignatureAlgo)) {
                throw new CertifyException(ErrorConstants.INVALID_QR_SIGNING_ALGORITHM, "The algorithm " + qrSignatureAlgo + " is not supported for QR signing. The supported values are: " + keyAliasMapper.keySet());
            }
            QrSettingsValidator.validateQrSettings(qrSettings, vcTemplate);
        }
    }

    private void validateKeyAliasMapperConfiguration(CredentialConfigurationDTO credentialConfig) {
        if(pluginMode.equals("VCIssuance")) {
            return;
        }
        String signatureCryptoSuite = credentialConfig.getSignatureCryptoSuite();
        String signatureAlgo = credentialConfig.getSignatureAlgo();

        if(signatureCryptoSuite != null) {
            if(!credentialSigningAlgValuesSupportedMap.containsKey(signatureCryptoSuite)) {
                throw new CertifyException(ErrorConstants.UNSUPPORTED_CRYPTO_SUITE, "Unsupported signature crypto suite: " + signatureCryptoSuite);
            }

            List<String> signatureAlgos = credentialSigningAlgValuesSupportedMap.get(signatureCryptoSuite);
            if(!signatureAlgos.contains(signatureAlgo)) {
                throw new CertifyException(ErrorConstants.UNSUPPORTED_SIGNATURE_ALGO, "Signature algorithm " + signatureAlgo + " is not supported for the crypto suite: " + signatureCryptoSuite);
            }
        }

        List<List<String>> keyAliasList = keyAliasMapper.get(credentialConfig.getSignatureAlgo());
        if (keyAliasList == null || keyAliasList.isEmpty()) {
            throw new CertifyException(ErrorConstants.KEY_CHOOSER_CONFIG_NOT_FOUND, "No key chooser configuration found for the signature crypto suite: " + credentialConfig.getSignatureCryptoSuite());
        }

        boolean isMatch = keyAliasList.stream()
                .anyMatch(pair ->
                        credentialConfig.getKeyManagerAppId() != null &&
                                pair.getFirst().equals(credentialConfig.getKeyManagerAppId()) &&
                                credentialConfig.getKeyManagerRefId() != null &&
                                pair.getLast().equals(credentialConfig.getKeyManagerRefId()));

        if (!isMatch && StringUtils.hasText(credentialConfig.getIssuerId())) {
            isMatch = issuerRepository.findById(credentialConfig.getIssuerId())
                    .map(issuer -> matchesIssuerSigningKeys(credentialConfig, issuer))
                    .orElse(false);
        }

        if (!isMatch) {
            throw new CertifyException(ErrorConstants.KEY_CHOOSER_APP_REF_NOT_FOUND, "No matching appId and refId found in the key chooser configuration.");
        }
    }

    private void applyIssuerSigningKeys(CredentialConfigurationDTO credentialConfig, Issuer issuer) {
        // mso_mdoc signs with issuer Document Signer (mdocDs*), not LDP DID keys.
        if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat())) {
            return;
        }
        if (!StringUtils.hasText(issuer.getKeyManagerAppId())) {
            return;
        }
        if (!IssuerConstants.DEFAULT_ISSUER_ID.equals(issuer.getIssuerId())) {
            credentialConfig.setKeyManagerAppId(issuer.getKeyManagerAppId());
            credentialConfig.setKeyManagerRefId(issuer.getKeyManagerRefId());
            if (!StringUtils.hasText(credentialConfig.getSignatureAlgo())) {
                credentialConfig.setSignatureAlgo(issuer.getSignatureAlgo());
            }
            if (!StringUtils.hasText(credentialConfig.getSignatureCryptoSuite())) {
                credentialConfig.setSignatureCryptoSuite(issuer.getSignatureCryptoSuite());
            }
            return;
        }
        if (!StringUtils.hasText(credentialConfig.getKeyManagerAppId())) {
            credentialConfig.setKeyManagerAppId(issuer.getKeyManagerAppId());
            credentialConfig.setKeyManagerRefId(issuer.getKeyManagerRefId());
            if (!StringUtils.hasText(credentialConfig.getSignatureAlgo())) {
                credentialConfig.setSignatureAlgo(issuer.getSignatureAlgo());
            }
            if (!StringUtils.hasText(credentialConfig.getSignatureCryptoSuite())) {
                credentialConfig.setSignatureCryptoSuite(issuer.getSignatureCryptoSuite());
            }
        }
    }

    private void validateIssuerCredentialBinding(CredentialConfigurationDTO credentialConfig, Issuer issuer) {
        if (IssuerConstants.DEFAULT_ISSUER_ID.equals(issuer.getIssuerId())) {
            return;
        }
        if (!issuer.getIssuerId().equals(credentialConfig.getIssuerId())) {
            throw new CertifyException(ErrorConstants.CROSS_ISSUER_CONFIG_MISMATCH,
                    "Credential configuration issuerId must match the target issuer: " + issuer.getIssuerId());
        }
        // mso_mdoc uses issuer mdoc DS/IACA PKI; do not require LDP keyManager* binding.
        if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat())) {
            return;
        }
        if (StringUtils.hasText(issuer.getKeyManagerAppId())
                && !issuer.getKeyManagerAppId().equals(credentialConfig.getKeyManagerAppId())) {
            throw new CertifyException(ErrorConstants.CROSS_ISSUER_CONFIG_MISMATCH,
                    "keyManagerAppId must match the onboarded issuer signing keys");
        }
        if (StringUtils.hasText(issuer.getKeyManagerRefId())
                && !issuer.getKeyManagerRefId().equals(credentialConfig.getKeyManagerRefId())) {
            throw new CertifyException(ErrorConstants.CROSS_ISSUER_CONFIG_MISMATCH,
                    "keyManagerRefId must match the onboarded issuer signing keys");
        }
    }

    private boolean matchesIssuerSigningKeys(CredentialConfigurationDTO credentialConfig, Issuer issuer) {
        return StringUtils.hasText(credentialConfig.getKeyManagerAppId())
                && credentialConfig.getKeyManagerAppId().equals(issuer.getKeyManagerAppId())
                && StringUtils.hasText(credentialConfig.getKeyManagerRefId())
                && credentialConfig.getKeyManagerRefId().equals(issuer.getKeyManagerRefId());
    }

    /**
     * Validates cryptographic_binding_methods_supported, credential_signing_alg_values_supported and
     * proof_types_supported and stores them on the entity.
     * <p>
     * All three are mandatory on add and on update. The deployment configuration is the allow-list every
     * value is checked against, and never a source of values: nothing is filled in from it, so what a
     * configuration advertises is always what the issuer declared for it.
     * <p>
     * credential_signing_alg_values_supported is not taken from the request. It is what the credential is
     * signed with: the crypto suite for ldp_vc, the signatureAlgo for every other format, so what is
     * advertised and what is used to sign can never disagree.
     * <p>
     * A value listed more than once is kept once, in the order first given, and the request is not
     * rejected for it. This happens before validation, so a repeated value is also reported only once.
     * <p>
     * Every failure across all three attributes is collected before anything is stored, so the caller
     * sees the whole payload's problems at once and nothing is partially saved.
     */
    private void validateAndApplyCredentialConfigMetadataAttributes(CredentialConfigurationDTO request, CredentialConfig credentialConfig) {
        // An mdoc's issuerAuth is signed with signatureAlgo alone, so a crypto suite sent with an mso_mdoc
        // request is not validated, and never stored.
        if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat())) {
            credentialConfig.setSignatureCryptoSuite(null);
        }
        List<String> bindingMethods = getDistinct(request.getCryptographicBindingMethodsSupported());
        String signatureAlgo = credentialConfig.getSignatureAlgo();
        Map<String, Object> proofTypes = getDistinctProofSigningAlgs(request.getProofTypesSupported());

        List<io.mosip.certify.core.dto.Error> errors = new ArrayList<>();
        CredentialConfigMetadataValidator.validateBindingMethods(bindingMethods,
                credentialConfig.getCredentialFormat(), cryptographicBindingMethodsSupportedMap, errors);
        int errorsBeforeSigningAlg = errors.size();
        CredentialConfigMetadataValidator.validateSigningAlg(signatureAlgo, credentialConfig.getCredentialFormat(),
                credentialConfig.getSignatureCryptoSuite(), credentialSigningAlgValuesSupportedMap,
                keyAliasMapper, pluginMode, errors);
        // An algorithm already rejected above is not reported a second time by the COSE check.
        if (errors.size() == errorsBeforeSigningAlg) {
            CredentialConfigMetadataValidator.validateCoseSigningAlg(signatureAlgo,
                    credentialConfig.getCredentialFormat(), COSE_ALGORITHM_INTEGER_MAP.keySet(), errors);
        }
        CredentialConfigMetadataValidator.validateProofTypes(proofTypes, proofTypesSupported, errors);

        if (!errors.isEmpty()) {
            throw new CredentialConfigValidationException(errors);
        }

        credentialConfig.setCryptographicBindingMethodsSupported(bindingMethods);
        credentialConfig.setCredentialSigningAlgValuesSupported(
                CredentialConfigMetadataResolver.resolveAdvertisedSigningAlgs(credentialConfig));
        credentialConfig.setProofTypesSupported(proofTypes);
    }

    private static <T> List<T> getDistinct(List<T> values) {
        return values == null ? null : new ArrayList<>(new LinkedHashSet<>(values));
    }

    /**
     * The proof types with each proof_signing_alg_values_supported list de-duplicated. A proof type name
     * cannot repeat, being a JSON object key. Any other shape is passed through unchanged for the
     * validator to report.
     */
    private static Map<String, Object> getDistinctProofSigningAlgs(Map<String, Object> proofTypes) {
        if (proofTypes == null) {
            return null;
        }
        Map<String, Object> result = new LinkedHashMap<>();
        proofTypes.forEach((proofType, detail) -> {
            if (detail instanceof Map<?, ?> detailMap
                    && detailMap.get(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED) instanceof List<?> algs) {
                Map<Object, Object> distinctDetail = new LinkedHashMap<>(detailMap);
                distinctDetail.put(Constants.PROOF_SIGNING_ALG_VALUES_SUPPORTED, getDistinct(algs));
                result.put(proofType, distinctDetail);
            } else {
                result.put(proofType, detail);
            }
        });
        return result;
    }

    @Override
    public CredentialConfigurationDTO getCredentialConfigurationById(String credentialConfigKeyId) {
        CredentialConfig credentialConfig = getActiveCredentialConfig(credentialConfigKeyId);

        CredentialConfigurationDTO credentialConfigurationDTO = credentialConfigMapper.toDto(credentialConfig);
        // Both are always returned; the signing algorithm is returned as signatureAlgo. The stored values are
        // returned as they are; a configuration created before these attributes were stored carries none,
        // and keeps returning the values it always has.
        if (credentialConfigurationDTO.getCryptographicBindingMethodsSupported() == null) {
            credentialConfigurationDTO.setCryptographicBindingMethodsSupported(
                    CredentialConfigMetadataResolver.deriveBindingMethods(credentialConfig.getCredentialFormat(),
                            cryptographicBindingMethodsSupportedMap));
        }
        Map<String, Object> storedProofTypes = credentialConfigurationDTO.getProofTypesSupported();
        credentialConfigurationDTO.setProofTypesSupported(CredentialConfigMetadataResolver.resolveProofTypes(
                storedProofTypes == null || storedProofTypes.isEmpty() ? proofTypesSupported : storedProofTypes,
                proofTypesSupported));
        return credentialConfigurationDTO;
    }

    private CredentialConfig getActiveCredentialConfig(String credentialConfigKeyId) {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId);

        if(optional.isEmpty()) {
            throw new CredentialConfigException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, "Configuration not found for the provided ID: " + credentialConfigKeyId);
        }

        CredentialConfig credentialConfig = optional.get();
        if(!credentialConfig.getStatus().equals(Constants.ACTIVE)) {
            throw new CertifyException(ErrorConstants.CONFIG_NOT_ACTIVE, "Configuration is inactive.");
        }
        return credentialConfig;
    }

    @Override
    public List<CredentialConfigurationDTO> listCredentialConfigurations(String issuerId) {
        Issuer issuer = issuerResolver.resolve(issuerResolver.resolveIssuerId(issuerId));
        return credentialConfigRepository.findByIssuerIdAndStatus(issuer.getIssuerId(), Constants.ACTIVE).stream()
                .map(credentialConfigMapper::toDto)
                .collect(Collectors.toList());
    }

    /**
     * NOTE: Using @credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(#id) will cause
     * an additional database lookup for CredentialConfig by id within the key generator.
     * This is a trade-off for using declarative @CacheEvict on this method signature.
     * The alternative is manual CacheManager.evict() after fetching the object once in this method.
     */
    @Override
    @CacheEvict(cacheNames = CREDENTIAL_CONFIG_CACHE_NAME, key = "@credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(#credentialConfigKeyId)", condition = "#credentialConfigKeyId != null")
    public CredentialConfigResponse updateCredentialConfiguration(String credentialConfigKeyId, CredentialConfigurationDTO credentialConfigurationDTO){
        Optional<CredentialConfig> optional = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId);

        if(optional.isEmpty()) {
            log.warn("Configuration not found for update with id: {}", credentialConfigKeyId);
            throw new CredentialConfigException(ErrorConstants.CONFIG_NOT_FOUND_FOR_UPDATE, "Configuration not found for update with ID: " + credentialConfigKeyId);
        }

        CredentialConfig credentialConfig = optional.get();
        Issuer issuer = issuerResolver.resolve(credentialConfig.getIssuerId());
        if (StringUtils.hasText(credentialConfigurationDTO.getIssuerId())
                && !issuer.getIssuerId().equals(credentialConfigurationDTO.getIssuerId())) {
            throw new CertifyException(ErrorConstants.CROSS_ISSUER_CONFIG_MISMATCH,
                    "Cannot change issuerId for an existing credential configuration");
        }
        credentialConfigurationDTO.setIssuerId(issuer.getIssuerId());
        applyIssuerSigningKeys(credentialConfigurationDTO, issuer);
        validateIssuerCredentialBinding(credentialConfigurationDTO, issuer);

        credentialConfigMapper.updateEntityFromDto(credentialConfigurationDTO, credentialConfig);

        validateCredentialConfiguration(credentialConfigMapper.toDto(credentialConfig), false);

        validateAndApplyCredentialConfigMetadataAttributes(credentialConfigurationDTO, credentialConfig);

        CredentialConfig savedConfig = credentialConfigRepository.save(credentialConfig);
        log.info("Updated credential configuration: {}", savedConfig.getConfigId());

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(savedConfig.getCredentialConfigKeyId());
        credentialConfigResponse.setStatus(savedConfig.getStatus());
        credentialConfigResponse.setIssuerId(savedConfig.getIssuerId());

        return credentialConfigResponse;
    }

    /**
     * NOTE: Using @credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(#id) will cause
     * an additional database lookup for CredentialConfig by id within the key generator.
     * This is a trade-off for using declarative @CacheEvict on this method signature.
     */
    @Override
    @Transactional
    @CacheEvict(cacheNames = CREDENTIAL_CONFIG_CACHE_NAME,
            key = "@credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(#credentialConfigKeyId)",
            beforeInvocation = true)
    public String deleteCredentialConfigurationById(String credentialConfigKeyId) {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId) ;

        if(optional.isEmpty()) {
            log.warn("Configuration not found for delete with id: {}", credentialConfigKeyId);
            throw new CredentialConfigException(ErrorConstants.CONFIG_NOT_FOUND_FOR_DELETE, "Configuration not found for delete with ID: " + credentialConfigKeyId);
        }

        // The object is fetched once here.
        // The @CacheEvict's key SpEL will cause CredentialCacheKeyGenerator to fetch it again.
        credentialConfigRepository.delete(optional.get());
        log.info("Deleted credential configuration: {}", credentialConfigKeyId);
        return credentialConfigKeyId;
    }

    @Override
    public CredentialIssuerMetadataDTO fetchCredentialIssuerMetadata(String issuerId) {
        Issuer issuer = issuerResolver.resolve(issuerResolver.resolveIssuerId(issuerId));
        return buildMetadata(activeConfigs(issuer), issuer);
    }

    @Override
    public CredentialIssuerMetadataDTO fetchWellKnownMetadata(String issuerId) {
        Issuer issuer = issuerResolver.resolve(issuerResolver.resolveIssuerId(issuerId));
        return buildMetadata(filterForWellKnown(activeConfigs(issuer)), issuer);
    }

    private List<CredentialConfig> activeConfigs(Issuer issuer) {
        return credentialConfigRepository.findByIssuerIdAndStatus(issuer.getIssuerId(), Constants.ACTIVE);
    }

    private List<CredentialConfig> filterForWellKnown(List<CredentialConfig> credentialConfigList) {
        if (!StringUtils.hasText(wellKnownSupportedFormats)) {
            return credentialConfigList;
        }
        Set<String> allowedFormats = Arrays.stream(wellKnownSupportedFormats.split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .collect(Collectors.toSet());
        if (allowedFormats.isEmpty()) {
            return credentialConfigList;
        }
        return credentialConfigList.stream()
                .filter(config -> allowedFormats.contains(config.getCredentialFormat()))
                .collect(Collectors.toList());
    }


    /**
     * Checks every active configuration once the application is up, so a stored configuration that cannot
     * be advertised is reported at startup rather than first noticed by a wallet. It is logged, not fatal:
     * the metadata endpoint skips such a configuration and keeps serving the rest.
     *
     * <p>It runs outside the class-level transaction. Inside it, a failed load would mark that transaction
     * rollback-only, and committing it would then fail startup even though the error was caught.
     */
    @EventListener(ApplicationReadyEvent.class)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void validateStoredConfigurations() {
        List<CredentialConfig> active;
        try {
            active = credentialConfigRepository.findAll()
                    .stream()
                    .filter(config -> Constants.ACTIVE.equals(config.getStatus()))
                    .toList();
        } catch (RuntimeException e) {
            log.error("Stored credential configurations could not be loaded for the startup check", e);
            return;
        }
        long invalid = active.stream().filter(config -> tryBuildSupportedDTO(config) == null).count();
        if (invalid > 0) {
            log.error("{} of {} active credential configurations cannot be advertised in the issuer metadata",
                    invalid, active.size());
        }
    }

    private CredentialIssuerMetadataDTO buildMetadata(List<CredentialConfig> credentialConfigList, Issuer issuer) {
        CredentialIssuerMetadataDTO credentialIssuerMetadata = new CredentialIssuerMetadataDTO();
        Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedMap = new HashMap<>();

        for (CredentialConfig credentialConfig : credentialConfigList) {
            CredentialConfigurationSupportedDTO dto = tryBuildSupportedDTO(credentialConfig);
            if (dto != null) {
                credentialConfigurationSupportedMap.put(credentialConfig.getCredentialConfigKeyId(), dto);
            }
        }

        credentialIssuerMetadata.setCredentialConfigurationSupportedDTO(credentialConfigurationSupportedMap);
        populateCommonMetadataFields(credentialIssuerMetadata, issuer);
        return credentialIssuerMetadata;
    }

    /**
     * One configuration that cannot be advertised must not take the issuer metadata down for every
     * credential type, so the failure is logged against that configuration and it is left out.
     *
     * @return the advertised entry, or {@code null} when this configuration cannot be advertised
     */
    private CredentialConfigurationSupportedDTO tryBuildSupportedDTO(CredentialConfig credentialConfig) {
        try {
            return buildSupportedDTO(credentialConfig);
        } catch (RuntimeException e) {
            log.error("Credential configuration {} is left out of the issuer metadata: {}",
                    credentialConfig.getCredentialConfigKeyId(), e.getMessage(), e);
            return null;
        }
    }

    private CredentialConfigurationSupportedDTO buildSupportedDTO(CredentialConfig credentialConfig) {
        CredentialConfigurationSupportedDTO dto = mapToSupportedDTO(credentialConfig);
        // The configuration advertises what it signs with - its crypto suite for ldp_vc, its algorithm
        // otherwise - so a wallet is never told of something the credential is not actually signed with.
        List<String> algs = CredentialConfigMetadataResolver.resolveAdvertisedSigningAlgs(credentialConfig);
        if (algs.isEmpty()) {
            algs = null;
        }

        // A configuration written before these attributes were stored carries neither, so the same
        // defaults the Get API resolves are applied here too - what a wallet reads and what an
        // issuer reads back stay the same.
        if (dto.getCryptographicBindingMethodsSupported() == null) {
            dto.setCryptographicBindingMethodsSupported(
                    CredentialConfigMetadataResolver.deriveBindingMethods(credentialConfig.getCredentialFormat(),
                            cryptographicBindingMethodsSupportedMap));
        }
        Map<String, Object> storedProofTypes = credentialConfig.getProofTypesSupported();
        dto.setProofTypesSupported(CredentialConfigMetadataResolver.resolveProofTypes(
                storedProofTypes == null || storedProofTypes.isEmpty() ? proofTypesSupported : storedProofTypes,
                proofTypesSupported));

        if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat()) && algs != null) {
            List<Object> coseAlgs = new ArrayList<>();
            for (String alg : algs) {
                coseAlgs.add(getCoseAlgorithm(alg));
            }
            dto.setCredentialSigningAlgValuesSupported(coseAlgs);
        } else {
            dto.setCredentialSigningAlgValuesSupported(algs != null ? new ArrayList<>(algs) : null);
        }
        return dto;
    }

    public Integer getCoseAlgorithm(String signAlgorithm) {
        if (signAlgorithm == null) {
            throw new IllegalArgumentException("Missing COSE signing algorithm");
        }
        Integer coseAlg = COSE_ALGORITHM_INTEGER_MAP.get(signAlgorithm);
        if (coseAlg == null) {
            throw new IllegalArgumentException("Unsupported COSE signing algorithm for mso_mdoc: " + signAlgorithm);
        }
        return coseAlg;
    }

    private void populateCommonMetadataFields(CredentialIssuerMetadataDTO metadata, Issuer issuer) {
        metadata.setCredentialIssuer(issuer.getCredentialIssuerUrl());
        metadata.setAuthorizationServers(resolveAuthorizationServers(issuer));
        metadata.setCredentialEndpoint(IssuerUrlUtil.buildCredentialEndpoint(credentialIssuer, "latest"));
        metadata.setDisplay(mapIssuerDisplay(issuer));
        if (allowCNonce) metadata.setNonceEndpoint(IssuerUrlUtil.buildNonceEndpoint(credentialIssuer));
    }

    private List<Map<String, Object>> mapIssuerDisplay(Issuer issuer) {
        if (issuer.getDisplay() == null || issuer.getDisplay().isEmpty()) {
            return issuerDisplay;
        }
        return issuer.getDisplay().stream()
                .map(display -> {
                    Map<String, Object> map = new LinkedHashMap<>();
                    map.put("name", display.getName());
                    map.put("locale", display.getLocale());
                    return map;
                })
                .collect(Collectors.toList());
    }

    private List<String> resolveAuthorizationServers(Issuer issuer) {
        Set<String> allServers = new LinkedHashSet<>();

        if (issuer.getAuthorizationServers() != null) {
            issuer.getAuthorizationServers().stream()
                    .filter(StringUtils::hasText)
                    .map(String::trim)
                    .forEach(allServers::add);
        }

        if (allServers.isEmpty() && StringUtils.hasText(authUrl)) {
            Arrays.stream(authUrl.split(","))
                    .map(String::trim)
                    .filter(StringUtils::hasText)
                    .forEach(allServers::add);
        }

        if (authorizationServerMapping != null) {
            authorizationServerMapping.values().stream()
                    .filter(StringUtils::hasText)
                    .map(String::trim)
                    .forEach(allServers::add);
        }

        if (allServers.isEmpty()) {
            return Collections.singletonList(authUrl);
        }

        return new ArrayList<>(allServers);
    }

    private CredentialConfigurationSupportedDTO mapToSupportedDTO(CredentialConfig credentialConfig) {
        CredentialConfigurationSupportedDTO credentialConfigurationSupported = new CredentialConfigurationSupportedDTO();
        CredentialConfigurationDTO credentialConfigurationDTO = credentialConfigMapper.toDto(credentialConfig);
        credentialConfigurationSupported.setFormat(credentialConfigurationDTO.getCredentialFormat());
        credentialConfigurationSupported.setScope(credentialConfigurationDTO.getScope());
        credentialConfigurationSupported.setCryptographicBindingMethodsSupported(credentialConfig.getCryptographicBindingMethodsSupported());
        credentialConfigurationSupported.setProofTypesSupported(credentialConfig.getProofTypesSupported());

        CredentialMetadataDTO credentialMetadataDTO = new CredentialMetadataDTO();
        credentialMetadataDTO.setDisplay(credentialConfigurationDTO.getMetaDataDisplay());
        if (VCFormats.LDP_VC.equals(credentialConfig.getCredentialFormat())) {
            CredentialDefinition credentialDefinition = new CredentialDefinition();
            credentialDefinition.setType(credentialConfigurationDTO.getCredentialTypes());
            credentialDefinition.setContext(credentialConfigurationDTO.getContextURLs());
            credentialConfigurationSupported.setCredentialDefinition(credentialDefinition);
            credentialMetadataDTO.setClaims(mapStandardClaims(credentialConfig.getClaims()));
        } else if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat())) {
            credentialConfigurationSupported.setDocType(credentialConfig.getDocType());
            credentialMetadataDTO.setClaims(mapMDocClaims(credentialConfig.getMsoMdocClaims()));
        } else if (VCFormats.DC_SD_JWT.equals(credentialConfig.getCredentialFormat())) {
            credentialConfigurationSupported.setVct(credentialConfig.getSdJwtVct());
            credentialMetadataDTO.setClaims(mapStandardClaims(credentialConfig.getSdJwtClaims()));
        }
        credentialConfigurationSupported.setCredentialMetadataDTO(credentialMetadataDTO);

        return credentialConfigurationSupported;
    }

    private List<CredentialMetadataDTO.Claims> mapStandardClaims(Map<String, Claims> claims) {
        if (claims == null) return Collections.emptyList();
        return claims.entrySet().stream()
                .map(entry -> buildClaimObject(Collections.singletonList(entry.getKey()), entry.getValue()))
                .collect(Collectors.toList());
    }

    private List<CredentialMetadataDTO.Claims> mapMDocClaims(Map<String, Map<String, Claims>> mDocClaims) {
        if (mDocClaims == null) return Collections.emptyList();
        return mDocClaims.entrySet().stream()
                .filter(namespace -> namespace.getValue() != null)
                .flatMap(namespace -> namespace.getValue().entrySet().stream()
                        .map(entry -> buildClaimObject(Arrays.asList(namespace.getKey(), entry.getKey()), entry.getValue())))
                .collect(Collectors.toList());
    }

    private CredentialMetadataDTO.Claims buildClaimObject(List<String> path, Claims value) {
        CredentialMetadataDTO.Claims claim = new CredentialMetadataDTO.Claims();
        claim.setPath(path);
        if (value != null) {
            if (value.getDisplay() != null) {
                List<ClaimsDisplayFieldsConfigDTO.Display> displayList = value.getDisplay().stream()
                        .map(d -> new ClaimsDisplayFieldsConfigDTO.Display(d.getName(), d.getLocale()))
                        .collect(Collectors.toList());
                claim.setDisplay(displayList);
            }
            claim.setMandatory(value.isMandatory());
        }
        return claim;
    }
}