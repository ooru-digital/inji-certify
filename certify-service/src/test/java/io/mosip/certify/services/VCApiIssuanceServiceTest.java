package io.mosip.certify.services;

import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.core.dto.VCApiIssueOptions;
import io.mosip.certify.core.dto.VCApiIssueRequest;
import io.mosip.certify.core.dto.VCApiIssueResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
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

    @InjectMocks
    private VCApiIssuanceService vcApiIssuanceService;

    @Test
    public void issue_delegatesToTemplateSupport() {
        VCApiIssueRequest request = new VCApiIssueRequest();
        request.setCredentialSubject(Map.of("fullName", "Jane Doe"));
        VCApiIssueOptions options = new VCApiIssueOptions();
        options.setCredentialConfigurationId("farmer-credential");
        request.setOptions(options);

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("farmer-credential");
        config.setCredentialFormat(VCFormats.LDP_VC);
        when(credentialConfigurationService.getCredentialConfigurationById("farmer-credential")).thenReturn(config);

        JsonLDObject signedVc = JsonLDObject.fromJson("{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"]}");
        when(vcApiTemplateIssuanceSupport.issueFromTemplate(eq(request.getCredentialSubject()), eq(config)))
                .thenReturn(new VCApiTemplateIssuanceSupport.VCApiIssueResult(signedVc));

        VCApiIssueResponse response = vcApiIssuanceService.issue(request);

        assertNotNull(response.getVerifiableCredential());
        assertNotNull(response.getVerifiableCredential().get("type"));
        verify(credentialConfigurationService).getCredentialConfigurationById("farmer-credential");
        verify(vcApiTemplateIssuanceSupport).issueFromTemplate(any(), eq(config));
    }

    @Test
    public void issue_returnsCredentialMapFromSignedVc() {
        VCApiIssueRequest request = new VCApiIssueRequest();
        request.setCredentialSubject(Map.of("fullName", "Jane Doe", "idNumber", "12345"));
        VCApiIssueOptions options = new VCApiIssueOptions();
        options.setCredentialConfigurationId("farmer-credential");
        request.setOptions(options);

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("farmer-credential");
        config.setCredentialFormat(VCFormats.LDP_VC);
        when(credentialConfigurationService.getCredentialConfigurationById("farmer-credential")).thenReturn(config);

        JsonLDObject signedVc = JsonLDObject.fromJson(
                "{\"type\":[\"VerifiableCredential\",\"FarmerCredential\"],\"credentialSubject\":{\"fullName\":\"Jane Doe\"}}");
        when(vcApiTemplateIssuanceSupport.issueFromTemplate(eq(request.getCredentialSubject()), eq(config)))
                .thenReturn(new VCApiTemplateIssuanceSupport.VCApiIssueResult(signedVc));

        VCApiIssueResponse response = vcApiIssuanceService.issue(request);

        assertEquals("Jane Doe", ((Map<?, ?>) response.getVerifiableCredential().get("credentialSubject")).get("fullName"));
    }

    @Test
    public void issue_whenTemplateSupportThrows_propagatesCertifyException() {
        VCApiIssueRequest request = new VCApiIssueRequest();
        request.setCredentialSubject(Map.of("fullName", "Jane Doe"));
        VCApiIssueOptions options = new VCApiIssueOptions();
        options.setCredentialConfigurationId("unknown-config");
        request.setOptions(options);

        CredentialConfigurationDTO config = new CredentialConfigurationDTO();
        config.setCredentialConfigKeyId("unknown-config");
        when(credentialConfigurationService.getCredentialConfigurationById("unknown-config")).thenReturn(config);
        when(vcApiTemplateIssuanceSupport.issueFromTemplate(any(), eq(config)))
                .thenThrow(new CertifyException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, "Config not found"));

        CertifyException ex = assertThrows(CertifyException.class, () -> vcApiIssuanceService.issue(request));
        assertEquals(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, ex.getErrorCode());
    }
}
