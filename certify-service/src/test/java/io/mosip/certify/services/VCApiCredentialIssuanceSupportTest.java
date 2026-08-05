package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialLedgerService;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.credential.W3CJsonLD;
import io.mosip.certify.utils.LedgerUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class VCApiCredentialIssuanceSupportTest {

    private static final String DID_URL = "did:web:test.issuer";

    @InjectMocks
    private VCApiCredentialIssuanceSupport support;

    @Mock
    private CredentialFactory credentialFactory;
    @Mock
    private StatusListCredentialService statusListCredentialService;
    @Mock
    private CredentialLedgerService credentialLedgerService;
    @Mock
    private LedgerUtils ledgerUtils;

    @Before
    public void setUp() {
        ReflectionTestUtils.setField(support, "isLedgerEnabled", false);
    }

    @Test
    public void issueValidatedCredential_throws_whenProofPresent() {
        Map<String, Object> credential = validCredential();
        credential.put("proof", Map.of("type", "DataIntegrityProof"));

        CertifyException ex = assertThrows(CertifyException.class,
                () -> support.issueValidatedCredential(credential, ldpConfig()));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    @Test
    public void issueValidatedCredential_throws_whenUnsupportedFormat() {
        CredentialConfigurationDTO config = ldpConfig();
        config.setCredentialFormat(VCFormats.DC_SD_JWT);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> support.issueValidatedCredential(validCredential(), config));
        assertEquals(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT, ex.getErrorCode());
    }

    @Test
    public void issueValidatedCredential_throws_whenMissingVcdm2Context() {
        Map<String, Object> credential = validCredential();
        credential.put("@context", List.of("https://www.w3.org/2018/credentials/v1"));

        CertifyException ex = assertThrows(CertifyException.class,
                () -> support.issueValidatedCredential(credential, ldpConfig()));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    @Test
    public void issueValidatedCredential_throws_whenContextMismatch() {
        CredentialConfigurationDTO config = ldpConfig();
        config.setContextURLs(List.of(VCDM2Constants.URL, "https://example.org/missing-context"));

        CertifyException ex = assertThrows(CertifyException.class,
                () -> support.issueValidatedCredential(validCredential(), config));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    @Test
    public void issueValidatedCredential_throws_whenTypeMismatch() {
        CredentialConfigurationDTO config = ldpConfig();
        config.setCredentialTypes(List.of("VerifiableCredential", "OtherCredential"));

        CertifyException ex = assertThrows(CertifyException.class,
                () -> support.issueValidatedCredential(validCredential(), config));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    @Test
    public void issueValidatedCredential_throws_whenIssuerMismatch() {
        Map<String, Object> credential = validCredential();
        credential.put("issuer", "did:web:other.issuer");

        CertifyException ex = assertThrows(CertifyException.class,
                () -> support.issueValidatedCredential(credential, ldpConfig()));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    @Test
    public void issueValidatedCredential_success_signsWithoutStatus() throws Exception {
        CredentialConfigurationDTO config = ldpConfig();
        W3CJsonLD credentialBean = org.mockito.Mockito.mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(credentialBean));

        JsonLDObject signed = JsonLDObject.fromJson(
                "{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"],\"issuer\":\"" + DID_URL + "\"}");
        VCResult<JsonLDObject> result = new VCResult<>();
        result.setCredential(signed);
        when(credentialBean.addProof(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> result);

        VCApiCredentialIssuanceSupport.VCApiIssueResult issued =
                support.issueValidatedCredential(validCredential(), config);

        assertNotNull(issued.verifiableCredential());
        verify(statusListCredentialService, never()).addCredentialStatus(any(), anyString());
        verify(credentialLedgerService, never()).storeLedgerEntry(any(), any(), any(), any(), any(), any());
    }

    @Test
    public void issueValidatedCredential_addsStatusAndLedger_whenConfigured() throws Exception {
        ReflectionTestUtils.setField(support, "isLedgerEnabled", true);
        CredentialConfigurationDTO config = ldpConfig();
        config.setCredentialStatusPurposes(List.of("revocation"));

        W3CJsonLD credentialBean = org.mockito.Mockito.mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(credentialBean));
        JsonLDObject signed = JsonLDObject.fromJson("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        VCResult<JsonLDObject> result = new VCResult<>();
        result.setCredential(signed);
        when(credentialBean.addProof(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> result);
        when(ledgerUtils.extractIndexedAttributes(any())).thenReturn(Map.of());
        when(ledgerUtils.extractCredentialStatusDetails(any())).thenReturn(null);

        support.issueValidatedCredential(validCredential(), config);

        verify(statusListCredentialService).addCredentialStatus(any(), eq("revocation"));
        verify(credentialLedgerService).storeLedgerEntry(eq("http://example.gov/credentials/1"), eq(DID_URL),
                anyString(), any(), any(), any());
    }

    @Test
    public void issueValidatedCredential_throws_whenSubjectHasExtraFields() {
        CredentialConfigurationDTO config = ldpConfig();
        Map<String, Object> credential = validCredential();
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("id", "did:example:holder");
        subject.put("fullName", "Jane Doe");
        subject.put("email", "extra@example.com");
        credential.put("credentialSubject", subject);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> support.issueValidatedCredential(credential, config));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    @Test
    public void issueValidatedCredential_allowsSubjectIdEvenIfNotInTemplate() throws Exception {
        CredentialConfigurationDTO config = ldpConfig();
        // template has fullName only; request may still include JSON-LD id
        config.setVcTemplate("""
                {
                  "credentialSubject": {
                    "fullName": "${fullName}"
                  }
                }
                """);
        Map<String, Object> credential = validCredential();
        credential.put("credentialSubject", Map.of("id", "did:example:holder", "fullName", "Jane Doe"));

        W3CJsonLD credentialBean = org.mockito.Mockito.mock(W3CJsonLD.class);
        when(credentialFactory.getCredential(VCFormats.LDP_VC)).thenReturn(Optional.of(credentialBean));
        JsonLDObject signed = JsonLDObject.fromJson("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        VCResult<JsonLDObject> result = new VCResult<>();
        result.setCredential(signed);
        when(credentialBean.addProof(anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenAnswer(invocation -> result);

        assertNotNull(support.issueValidatedCredential(credential, config).verifiableCredential());
    }

    @Test
    public void issueValidatedCredential_throws_whenTemplateMissing() {
        CredentialConfigurationDTO config = ldpConfig();
        config.setVcTemplate(null);

        CertifyException ex = assertThrows(CertifyException.class,
                () -> support.issueValidatedCredential(validCredential(), config));
        assertEquals(ErrorConstants.INVALID_REQUEST, ex.getErrorCode());
    }

    private Map<String, Object> validCredential() {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("@context", List.of(VCDM2Constants.URL, "https://example.org/examples/v2"));
        credential.put("id", "http://example.gov/credentials/1");
        credential.put("type", List.of("VerifiableCredential", "FarmerCredential"));
        credential.put("issuer", DID_URL);
        credential.put("validFrom", "2026-01-01T00:00:00.000Z");
        credential.put("credentialSubject", Map.of("id", "did:example:holder", "fullName", "Jane Doe"));
        return credential;
    }

    private CredentialConfigurationDTO ldpConfig() {
        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("farmer-credential");
        config.setCredentialFormat(VCFormats.LDP_VC);
        config.setContextURLs(List.of(VCDM2Constants.URL, "https://example.org/examples/v2"));
        config.setCredentialTypes(List.of("VerifiableCredential", "FarmerCredential"));
        config.setDidUrl(DID_URL);
        config.setKeyManagerAppId("CERTIFY_VC_SIGN_ED25519");
        config.setKeyManagerRefId("ED25519_SIGN");
        config.setSignatureAlgo("Ed25519");
        config.setSignatureCryptoSuite("Ed25519Signature2020");
        config.setVcTemplate("""
                {
                  "@context": ["https://www.w3.org/ns/credentials/v2", "https://example.org/examples/v2"],
                  "type": ["VerifiableCredential", "FarmerCredential"],
                  "issuer": "${_issuer}",
                  "credentialSubject": {
                    "id": "${_holderId}",
                    "fullName": "${fullName}"
                  }
                }
                """);
        return config;
    }
}
