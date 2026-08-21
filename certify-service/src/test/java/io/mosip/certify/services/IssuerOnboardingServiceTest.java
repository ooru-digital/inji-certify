package io.mosip.certify.services;

import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.mdoc.MdocPkiRefs;
import io.mosip.certify.mdoc.MdocPkiService;
import io.mosip.certify.repository.IssuerRepository;
import io.mosip.certify.utils.IssuerMapper;
import io.mosip.kernel.keymanagerservice.repository.KeyPolicyRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class IssuerOnboardingServiceTest {

    @Mock
    private IssuerRepository issuerRepository;
    @Mock
    private KeymanagerService keymanagerService;
    @Mock
    private KeyPolicyRepository keyPolicyRepository;
    @Mock
    private IssuerMapper issuerMapper;
    @Mock
    private MdocPkiService mdocPkiService;

    @InjectMocks
    private IssuerOnboardingService issuerOnboardingService;

    @Before
    public void setUp() {
        ReflectionTestUtils.setField(issuerOnboardingService, "domainUrl",
                "https://collectible-dissentiently-arie.ngrok-free.dev/certify");
        ReflectionTestUtils.setField(issuerOnboardingService, "servletPath", "/v1/certify");
        ReflectionTestUtils.setField(issuerOnboardingService, "authUrl", "https://esignet.example.com");
        ReflectionTestUtils.setField(issuerOnboardingService, "keyPolicyValidityDays", 1095);
        ReflectionTestUtils.setField(issuerOnboardingService, "keyPolicyPreExpireDays", 60);

        LinkedHashMap<String, List<String>> signingMap = new LinkedHashMap<>();
        signingMap.put("Ed25519Signature2020", List.of("EdDSA"));
        ReflectionTestUtils.setField(issuerOnboardingService, "credentialSigningAlgValuesSupportedMap", signingMap);

        Map<String, List<List<String>>> keyAliasMapper = new HashMap<>();
        keyAliasMapper.put("EdDSA", List.of(List.of("CERTIFY_VC_SIGN_ED25519", "ED25519_SIGN")));
        ReflectionTestUtils.setField(issuerOnboardingService, "keyAliasMapper", keyAliasMapper);

        when(issuerMapper.mapDisplayToEntity(any())).thenReturn(Collections.emptyList());
        when(mdocPkiService.provision(anyString())).thenReturn(
                new MdocPkiRefs("iaca-app", "iaca-ref", "ds-app", "ds-ref"));
        when(keyPolicyRepository.findByApplicationId(anyString())).thenReturn(Optional.empty());
        when(issuerRepository.save(any(Issuer.class))).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    public void onboard_setsUniqueCredentialIssuerUrlAndPathBasedWellKnown() {
        IssuerOnboardingRequest request = newRequest("iiitb-ac");

        IssuerOnboardingResponse response = issuerOnboardingService.onboard(request);

        assertEquals("https://collectible-dissentiently-arie.ngrok-free.dev/certify/iiitb-ac",
                response.getCredentialIssuerUrl());
        assertEquals("https://collectible-dissentiently-arie.ngrok-free.dev/certify/iiitb-ac",
                response.getIdentifier());
        assertEquals(
                "https://collectible-dissentiently-arie.ngrok-free.dev/certify/iiitb-ac/.well-known/openid-credential-issuer",
                response.getWellKnownEndpoints().get("openidCredentialIssuer"));
        assertFalse(response.getWellKnownEndpoints().get("openidCredentialIssuer").contains("issuerId="));

        ArgumentCaptor<Issuer> captor = ArgumentCaptor.forClass(Issuer.class);
        verify(issuerRepository).save(captor.capture());
        assertEquals("https://collectible-dissentiently-arie.ngrok-free.dev/certify/iiitb-ac",
                captor.getValue().getCredentialIssuerUrl());
    }

    @Test
    public void onboard_rejectsReservedIssuerId() {
        IssuerOnboardingRequest request = newRequest("issuance");
        CertifyException ex = assertThrows(CertifyException.class, () -> issuerOnboardingService.onboard(request));
        assertTrue(ex.getMessage().contains("reserved issuerId"));
        verify(issuerRepository, never()).save(any());
    }

    private IssuerOnboardingRequest newRequest(String issuerId) {
        IssuerOnboardingRequest request = new IssuerOnboardingRequest();
        request.setIssuerId(issuerId);
        request.setDidUrl("did:web:example.com:" + issuerId);
        MetaDataDisplayDTO display = new MetaDataDisplayDTO();
        display.setName("Test Issuer");
        display.setLocale("en");
        request.setDisplay(List.of(display));
        IssuerSigningConfigDTO signing = new IssuerSigningConfigDTO();
        signing.setSignatureCryptoSuite("Ed25519Signature2020");
        signing.setSignatureAlgo("EdDSA");
        request.setSigningConfig(signing);
        return request;
    }
}
