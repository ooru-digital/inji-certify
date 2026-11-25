package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.IssuerRepository;
import io.mosip.certify.utils.CredentialConfigMapper;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class CredentialConfigurationMultiIssuerTest {

    private static final String ISSUER_ID = "issuer-a";

    @Mock
    private CredentialConfigRepository credentialConfigRepository;
    @Mock
    private CredentialConfigMapper credentialConfigMapper;
    @Mock
    private IssuerResolver issuerResolver;
    @Mock
    private IssuerRepository issuerRepository;
    @InjectMocks
    private CredentialConfigurationServiceImpl service;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        ReflectionTestUtils.setField(service, "credentialIssuer", "http://example.com");
        ReflectionTestUtils.setField(service, "cryptographicBindingMethodsSupportedMap", new LinkedHashMap<>());
        ReflectionTestUtils.setField(service, "proofTypesSupported", new LinkedHashMap<>());
        ReflectionTestUtils.setField(service, "issuerDisplay", List.of());
        ReflectionTestUtils.setField(service, "wellKnownSupportedFormats", VCFormats.LDP_VC);

        Issuer issuer = new Issuer();
        issuer.setIssuerId(ISSUER_ID);
        issuer.setCredentialIssuerUrl("http://example.com/" + ISSUER_ID);
        when(issuerResolver.resolveIssuerId(ISSUER_ID)).thenReturn(ISSUER_ID);
        when(issuerResolver.resolve(ISSUER_ID)).thenReturn(issuer);
        when(credentialConfigMapper.toDto(any(CredentialConfig.class))).thenAnswer(invocation -> {
            CredentialConfig config = invocation.getArgument(0);
            CredentialConfigurationDTO dto = new CredentialConfigurationDTO();
            dto.setCredentialFormat(config.getCredentialFormat());
            return dto;
        });
        when(credentialConfigRepository.findByIssuerIdAndStatus(ISSUER_ID, "active"))
                .thenReturn(List.of(config("ldp", VCFormats.LDP_VC), config("sdjwt", VCFormats.DC_SD_JWT)));
    }

    @Test
    public void wellKnownMetadata_isFilteredAndUsesIssuerUrl() {
        CredentialIssuerMetadataDTO metadata = service.fetchWellKnownMetadata(ISSUER_ID);

        assertEquals("http://example.com/" + ISSUER_ID, metadata.getCredentialIssuer());
        assertEquals(Set.of("ldp"), metadata.getCredentialConfigurationSupportedDTO().keySet());
    }

    @Test
    public void issuanceMetadata_isNotRestrictedToAdvertisedFormats() {
        CredentialIssuerMetadataDTO metadata = service.fetchCredentialIssuerMetadata(ISSUER_ID);

        assertEquals(Set.of("ldp", "sdjwt"), metadata.getCredentialConfigurationSupportedDTO().keySet());
    }

    @Test
    public void update_rejectsMovingConfigurationToAnotherIssuer() {
        CredentialConfig stored = config("ldp", VCFormats.LDP_VC);
        stored.setIssuerId(ISSUER_ID);
        when(credentialConfigRepository.findByCredentialConfigKeyId("ldp")).thenReturn(Optional.of(stored));
        CredentialConfigurationDTO request = new CredentialConfigurationDTO();
        request.setIssuerId("issuer-b");

        CertifyException ex = assertThrows(CertifyException.class,
                () -> service.updateCredentialConfiguration("ldp", request));
        assertEquals(ErrorConstants.CROSS_ISSUER_CONFIG_MISMATCH, ex.getErrorCode());
    }

    private static CredentialConfig config(String id, String format) {
        CredentialConfig config = new CredentialConfig();
        config.setCredentialConfigKeyId(id);
        config.setCredentialFormat(format);
        config.setStatus("active");
        config.setSignatureAlgo("EdDSA");
        return config;
    }
}
