package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.config.VelocityEnvConfig;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialLedgerService;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.credential.W3CJsonLD;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.utils.CredentialCacheKeyGenerator;
import io.mosip.certify.utils.LedgerUtils;
import io.mosip.certify.vcformatters.VCFormatter;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.ArgumentCaptor;
import org.json.JSONObject;

@RunWith(MockitoJUnitRunner.class)
public class VCApiTemplateIssuanceSupportTest {

    private static final String TEMPLATE_NAME = "FarmerCredential|https://www.w3.org/2018/credentials/v1";
    private static final String DID_URL = "did:web:test.issuer";

    @InjectMocks
    private VCApiTemplateIssuanceSupport support;

    @Mock
    private CredentialCacheKeyGenerator credentialCacheKeyGenerator;
    @Mock
    private VCFormatter vcFormatter;
    @Mock
    private CredentialFactory credentialFactory;
    @Mock
    private StatusListCredentialService statusListCredentialService;
    @Mock
    private CredentialLedgerService credentialLedgerService;
    @Mock
    private LedgerUtils ledgerUtils;
    @Mock
    private VelocityEnvConfig velocityEnvConfig;
    @Mock
    private IssuerResolver issuerResolver;

    @Before
    public void setUp() {
        ReflectionTestUtils.setField(support, "didUrl", DID_URL);
        ReflectionTestUtils.setField(support, "renderTemplateId", "");
        ReflectionTestUtils.setField(support, "idPrefix", "");
        ReflectionTestUtils.setField(support, "defaultExpiryDuration", "P730D");
        ReflectionTestUtils.setField(support, "isLedgerEnabled", false);
        when(velocityEnvConfig.getEnvConfigs()).thenReturn(new HashMap<>());
        Issuer issuer = new Issuer();
        issuer.setIssuerId("farmer");
        issuer.setDidUrl(DID_URL);
        issuer.setIdentifier("https://test.issuer");
        when(issuerResolver.resolve(any())).thenReturn(issuer);
    }

    @Test
    public void resolveTemplateName_returnsTemplateName_whenMappingExists() {
        when(credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId("farmer-credential"))
                .thenReturn(TEMPLATE_NAME);

        assertEquals(TEMPLATE_NAME, support.resolveTemplateName("farmer-credential"));
    }

    @Test
    public void resolveTemplateName_throwsCertifyException_whenTemplateNotFound() {
        when(credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId("missing-config"))
                .thenReturn("default-key");

        CertifyException ex = assertThrows(CertifyException.class,
                () -> support.resolveTemplateName("missing-config"));
        assertEquals(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, ex.getErrorCode());
    }

    @Test
    public void issueFromTemplate_throwsCertifyException_whenUnsupportedFormat() {
        CredentialConfigurationDTO config = ldpConfig();
        config.setCredentialFormat(VCFormats.DC_SD_JWT);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> support.issueFromTemplate(Map.of("fullName", "Jane Doe"), config));
        assertEquals(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT, ex.getErrorCode());
    }

    @Test
    public void issueFromTemplate_success_withLdpVcFormat() throws Exception {
        CredentialConfigurationDTO config = ldpConfig();
        Map<String, Object> credentialSubject = Map.of("fullName", "Jane Doe", "id", "did:example:holder");
        stubSuccessfulIssuance(config, "{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");

        VCApiTemplateIssuanceSupport.VCApiIssueResult result =
                support.issueFromTemplate(credentialSubject, config);

        assertNotNull(result.verifiableCredential());
        assertNotNull(result.verifiableCredential().getJsonObject());
        verify(credentialFactory).getCredential(VCFormats.LDP_VC);
        verify(statusListCredentialService, never()).addCredentialStatus(any(), anyString(), any());
        verify(credentialLedgerService, never()).storeLedgerEntry(any(), any(), any(), any(), any(), any());
    }

    @Test
    public void issueFromTemplate_addsCredentialStatus_whenRevocationEnabledAndV2Context() throws Exception {
        CredentialConfigurationDTO config = ldpConfig();
        config.setContextURLs(List.of(VCDM2Constants.URL));
        when(credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(config.getCredentialConfigKeyId()))
                .thenReturn(TEMPLATE_NAME);
        when(vcFormatter.getCredentialStatusPurpose(TEMPLATE_NAME)).thenReturn(List.of("revocation"));
        stubCredentialSigning("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");

        support.issueFromTemplate(Map.of("fullName", "Jane Doe"), config);

        verify(statusListCredentialService).addCredentialStatus(any(), eq("revocation"), eq(issuer));
    }

    @Test
    public void issueFromTemplate_throwsCertifyException_whenUnsignedCredentialContainsProof() {
        CredentialConfigurationDTO config = ldpConfig();
        when(credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(config.getCredentialConfigKeyId()))
                .thenReturn(TEMPLATE_NAME);
        when(vcFormatter.getCredentialStatusPurpose(TEMPLATE_NAME)).thenReturn(Collections.emptyList());

        W3CJsonLD mockW3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(mockW3CJsonLD));
        when(mockW3CJsonLD.createCredential(anyMap(), eq(TEMPLATE_NAME)))
                .thenReturn("{\"type\":[\"VerifiableCredential\"],\"proof\":{}}");

        CertifyException ex = assertThrows(CertifyException.class,
                () -> support.issueFromTemplate(Map.of("fullName", "Jane Doe"), config));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    @Test
    public void issueFromTemplate_omitsBlankCredentialSubjectIdWhenNotProvided() throws Exception {
        CredentialConfigurationDTO config = ldpConfig();
        Map<String, Object> credentialSubject = Map.of("fullName", "Jane Doe");
        when(credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(config.getCredentialConfigKeyId()))
                .thenReturn(TEMPLATE_NAME);
        when(vcFormatter.getCredentialStatusPurpose(TEMPLATE_NAME)).thenReturn(Collections.emptyList());

        W3CJsonLD mockW3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(mockW3CJsonLD));
        when(mockW3CJsonLD.createCredential(anyMap(), eq(TEMPLATE_NAME)))
                .thenReturn("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"],\"credentialSubject\":{\"id\":\"\",\"fullName\":\"Jane Doe\"}}");
        when(vcFormatter.getProofAlgorithm(TEMPLATE_NAME)).thenReturn("EdDSA");
        when(vcFormatter.getAppID(TEMPLATE_NAME)).thenReturn("testAppId");
        when(vcFormatter.getRefID(TEMPLATE_NAME)).thenReturn("testRefId");
        when(vcFormatter.getDidUrl(TEMPLATE_NAME)).thenReturn("did:example:issuer");
        when(vcFormatter.getSignatureCryptoSuite(TEMPLATE_NAME)).thenReturn("Ed25519Signature2020");

        ArgumentCaptor<String> unsignedVcCaptor = ArgumentCaptor.forClass(String.class);
        VCResult mockVcResult = new VCResult();
        mockVcResult.setCredential(JsonLDObject.fromJson(
                "{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"],\"credentialSubject\":{\"fullName\":\"Jane Doe\"}}"));
        when(mockW3CJsonLD.addProof(unsignedVcCaptor.capture(), eq(""), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(mockVcResult);

        support.issueFromTemplate(credentialSubject, config);

        JSONObject unsignedVc = new JSONObject(unsignedVcCaptor.getValue());
        assertFalse(unsignedVc.getJSONObject("credentialSubject").has("id"));
        assertEquals("Jane Doe", unsignedVc.getJSONObject("credentialSubject").getString("fullName"));
    }

    @Test
    public void issueFromTemplate_storesLedgerEntry_whenLedgerEnabled() throws Exception {
        ReflectionTestUtils.setField(support, "isLedgerEnabled", true);
        CredentialConfigurationDTO config = ldpConfig();
        Map<String, Object> credentialSubject = Map.of("fullName", "Jane Doe");
        stubSuccessfulIssuance(config, "{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        when(ledgerUtils.extractIndexedAttributes(any())).thenReturn(Map.of("fullName", "Jane Doe"));
        when(ledgerUtils.extractCredentialStatusDetails(any())).thenReturn(null);

        support.issueFromTemplate(credentialSubject, config);

        verify(credentialLedgerService).storeLedgerEntry(isNull(), eq(DID_URL), eq("FarmerCredential,VerifiableCredential"),
                isNull(), anyMap(), any());
    }

    private CredentialConfigurationDTO ldpConfig() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("farmer-credential");
        config.setCredentialFormat(VCFormats.LDP_VC);
        config.setCredentialTypes(List.of("VerifiableCredential", "FarmerCredential"));
        config.setContextURLs(List.of("https://www.w3.org/2018/credentials/v1"));
        config.setIssuerId("farmer");
        return config;
    }

    private void stubSuccessfulIssuance(CredentialConfigurationDTO config, String signedJson) throws Exception {
        when(credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(config.getCredentialConfigKeyId()))
                .thenReturn(TEMPLATE_NAME);
        when(vcFormatter.getCredentialStatusPurpose(TEMPLATE_NAME)).thenReturn(Collections.emptyList());
        stubCredentialSigning(signedJson);
    }

    private void stubCredentialSigning(String signedJson) throws Exception {
        W3CJsonLD mockW3CJsonLD = mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(mockW3CJsonLD));
        when(mockW3CJsonLD.createCredential(anyMap(), eq(TEMPLATE_NAME)))
                .thenReturn("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        when(vcFormatter.getProofAlgorithm(TEMPLATE_NAME)).thenReturn("EdDSA");
        when(vcFormatter.getAppID(TEMPLATE_NAME)).thenReturn("testAppId");
        when(vcFormatter.getRefID(TEMPLATE_NAME)).thenReturn("testRefId");
        when(vcFormatter.getDidUrl(TEMPLATE_NAME)).thenReturn("did:example:issuer");
        when(vcFormatter.getSignatureCryptoSuite(TEMPLATE_NAME)).thenReturn("Ed25519Signature2020");

        VCResult mockVcResult = new VCResult();
        mockVcResult.setCredential(JsonLDObject.fromJson(signedJson));
        when(mockW3CJsonLD.addProof(anyString(), eq(""), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(mockVcResult);
    }
}
