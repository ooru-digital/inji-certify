/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.VCApiCredentialInput;
import io.mosip.certify.core.dto.VCApiIssueOptions;
import io.mosip.certify.core.dto.VCApiIssueRequest;
import io.mosip.certify.core.dto.VCApiIssueResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.utils.VcApiValidityResolver;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class VCApiIssuanceServiceTest {

    @Mock
    private CredentialConfigurationService credentialConfigurationService;

    @Mock
    private VCApiTemplateIssuanceSupport vcApiTemplateIssuanceSupport;

    @Mock
    private VcApiValidityResolver vcApiValidityResolver;

    @InjectMocks
    private VCApiIssuanceService vcApiIssuanceService;

    @Test
    public void issue_delegatesToTemplateSupport_forLdpVc() throws Exception {
        VCApiIssueRequest request = buildRequest("farmer-credential", Map.of("fullName", "Jane Doe"));
        VcApiValidityResolver.ValidityWindow validity =
                new VcApiValidityResolver.ValidityWindow("2026-01-01T00:00:00.000Z", "2028-01-01T00:00:00.000Z");

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("farmer-credential");
        config.setCredentialFormat(VCFormats.LDP_VC);
        when(credentialConfigurationService.getCredentialConfigurationById("farmer-credential")).thenReturn(config);
        when(vcApiValidityResolver.resolve(null, null)).thenReturn(validity);

        JsonLDObject signedVc = JsonLDObject.fromJson("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        when(vcApiTemplateIssuanceSupport.issueFromTemplate(eq(request.getCredential().getCredentialSubject()),
                eq(config), eq(validity)))
                .thenReturn(new VCApiTemplateIssuanceSupport.VCApiIssueResult(signedVc, VCFormats.LDP_VC));

        VCApiIssueResponse response = vcApiIssuanceService.issue(request);

        assertEquals(VCFormats.LDP_VC, response.getFormat());
        assertTrue(response.getVerifiableCredential() instanceof Map);
        assertNotNull(((Map<?, ?>) response.getVerifiableCredential()).get("type"));
        verify(credentialConfigurationService).getCredentialConfigurationById("farmer-credential");
        verify(vcApiTemplateIssuanceSupport).issueFromTemplate(any(), eq(config), eq(validity));
    }

    @Test
    public void issue_passesClientValidity_toTemplateSupport() throws Exception {
        VCApiIssueRequest request = buildRequest("farmer-credential", Map.of("fullName", "Jane Doe"));
        request.getCredential().setValidFrom("2026-07-24T06:30:00Z");
        request.getCredential().setValidUntil("2031-07-24T06:30:00Z");
        request.getCredential().setContext(List.of("https://www.w3.org/ns/credentials/v2"));
        request.getCredential().setType(List.of("VerifiableCredential", "FarmerCredential"));
        request.getCredential().setIssuer("did:web:ignored.example");

        VcApiValidityResolver.ValidityWindow validity =
                new VcApiValidityResolver.ValidityWindow("2026-07-24T06:30:00.000Z", "2031-07-24T06:30:00.000Z");

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("farmer-credential");
        config.setCredentialFormat(VCFormats.LDP_VC);
        when(credentialConfigurationService.getCredentialConfigurationById("farmer-credential")).thenReturn(config);
        when(vcApiValidityResolver.resolve("2026-07-24T06:30:00Z", "2031-07-24T06:30:00Z")).thenReturn(validity);

        JsonLDObject signedVc = JsonLDObject.fromJson("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        when(vcApiTemplateIssuanceSupport.issueFromTemplate(any(), eq(config), eq(validity)))
                .thenReturn(new VCApiTemplateIssuanceSupport.VCApiIssueResult(signedVc, VCFormats.LDP_VC));

        vcApiIssuanceService.issue(request);

        verify(vcApiValidityResolver).resolve("2026-07-24T06:30:00Z", "2031-07-24T06:30:00Z");
        verify(vcApiTemplateIssuanceSupport).issueFromTemplate(
                eq(Map.of("fullName", "Jane Doe")), eq(config), eq(validity));
    }

    @Test
    public void issue_returnsStringCredential_forMsoMdoc() throws Exception {
        VCApiIssueRequest request = buildRequest("mdl-credential", Map.of("family_name", "Doe"));
        VcApiValidityResolver.ValidityWindow validity =
                new VcApiValidityResolver.ValidityWindow("2026-01-01T00:00:00.000Z", "2028-01-01T00:00:00.000Z");

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("mdl-credential");
        config.setCredentialFormat(VCFormats.MSO_MDOC);
        when(credentialConfigurationService.getCredentialConfigurationById("mdl-credential")).thenReturn(config);
        when(vcApiValidityResolver.resolve(null, null)).thenReturn(validity);

        when(vcApiTemplateIssuanceSupport.issueFromTemplate(eq(request.getCredential().getCredentialSubject()),
                eq(config), eq(validity)))
                .thenReturn(new VCApiTemplateIssuanceSupport.VCApiIssueResult("base64url-mdoc", VCFormats.MSO_MDOC));

        VCApiIssueResponse response = vcApiIssuanceService.issue(request);

        assertEquals(VCFormats.MSO_MDOC, response.getFormat());
        assertEquals("base64url-mdoc", response.getVerifiableCredential());
    }

    @Test
    public void issue_returnsCredentialMapFromSignedVc() throws Exception {
        VCApiIssueRequest request = buildRequest("farmer-credential",
                Map.of("fullName", "Jane Doe", "idNumber", "12345"));
        VcApiValidityResolver.ValidityWindow validity =
                new VcApiValidityResolver.ValidityWindow("2026-01-01T00:00:00.000Z", "2028-01-01T00:00:00.000Z");

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("farmer-credential");
        config.setCredentialFormat(VCFormats.LDP_VC);
        when(credentialConfigurationService.getCredentialConfigurationById("farmer-credential")).thenReturn(config);
        when(vcApiValidityResolver.resolve(null, null)).thenReturn(validity);

        JsonLDObject signedVc = JsonLDObject.fromJson(
                "{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"],\"credentialSubject\":{\"fullName\":\"Jane Doe\"}}");
        when(vcApiTemplateIssuanceSupport.issueFromTemplate(eq(request.getCredential().getCredentialSubject()),
                eq(config), eq(validity)))
                .thenReturn(new VCApiTemplateIssuanceSupport.VCApiIssueResult(signedVc, VCFormats.LDP_VC));

        VCApiIssueResponse response = vcApiIssuanceService.issue(request);

        Map<?, ?> vc = (Map<?, ?>) response.getVerifiableCredential();
        assertEquals("Jane Doe", ((Map<?, ?>) vc.get("credentialSubject")).get("fullName"));
    }

    @Test
    public void issue_reordersLdpVcProperties_toVcdmExampleOrder() throws Exception {
        VCApiIssueRequest request = buildRequest("farmer-credential", Map.of("fullName", "Jane Doe"));
        VcApiValidityResolver.ValidityWindow validity =
                new VcApiValidityResolver.ValidityWindow("2026-07-24T06:30:00.000Z", "2031-07-24T06:30:00.000Z");

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("farmer-credential");
        config.setCredentialFormat(VCFormats.LDP_VC);
        when(credentialConfigurationService.getCredentialConfigurationById("farmer-credential")).thenReturn(config);
        when(vcApiValidityResolver.resolve(null, null)).thenReturn(validity);

        // Deliberately unordered input (credentialSubject / validUntil first)
        String unorderedVc = """
                {
                  "credentialSubject": {"fullName": "Jane Doe"},
                  "validUntil": "2031-07-24T06:30:00.000Z",
                  "validFrom": "2026-07-24T06:30:00.000Z",
                  "id": "urn:uuid:test",
                  "type": ["VerifiableCredential", "FarmerCredential"],
                  "@context": ["https://www.w3.org/ns/credentials/v2"],
                  "issuer": "did:web:example",
                  "credentialStatus": {"type": "BitstringStatusListEntry"},
                  "proof": {"type": "Ed25519Signature2020"}
                }
                """;
        JsonLDObject signedVc = JsonLDObject.fromJson(unorderedVc);
        when(vcApiTemplateIssuanceSupport.issueFromTemplate(any(), eq(config), eq(validity)))
                .thenReturn(new VCApiTemplateIssuanceSupport.VCApiIssueResult(signedVc, VCFormats.LDP_VC));

        VCApiIssueResponse response = vcApiIssuanceService.issue(request);

        @SuppressWarnings("unchecked")
        Map<String, Object> vc = (Map<String, Object>) response.getVerifiableCredential();
        assertEquals(List.of(
                "@context",
                "id",
                "type",
                "issuer",
                "validFrom",
                "validUntil",
                "credentialSubject",
                "credentialStatus",
                "proof"
        ), List.copyOf(vc.keySet()));
    }

    @Test
    public void issue_whenTemplateSupportThrows_propagatesCertifyException() throws Exception {
        VCApiIssueRequest request = buildRequest("unknown-config", Map.of("fullName", "Jane Doe"));
        VcApiValidityResolver.ValidityWindow validity =
                new VcApiValidityResolver.ValidityWindow("2026-01-01T00:00:00.000Z", "2028-01-01T00:00:00.000Z");

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("unknown-config");
        when(credentialConfigurationService.getCredentialConfigurationById("unknown-config")).thenReturn(config);
        when(vcApiValidityResolver.resolve(null, null)).thenReturn(validity);
        when(vcApiTemplateIssuanceSupport.issueFromTemplate(any(), eq(config), eq(validity)))
                .thenThrow(new CertifyException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, "Config not found"));

        CertifyException ex = assertThrows(CertifyException.class, () -> vcApiIssuanceService.issue(request));
        assertEquals(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, ex.getErrorCode());
    }

    private VCApiIssueRequest buildRequest(String configId, Map<String, Object> subject) {
        VCApiIssueRequest request = new VCApiIssueRequest();
        VCApiCredentialInput credential = new VCApiCredentialInput();
        credential.setCredentialSubject(subject);
        request.setCredential(credential);
        VCApiIssueOptions options = new VCApiIssueOptions();
        options.setCredentialConfigurationId(configId);
        request.setOptions(options);
        return request;
    }
}
