package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.dto.VcApiIssueOptions;
import io.mosip.certify.core.dto.VcApiIssueRequest;
import io.mosip.certify.core.dto.VcApiIssueResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.services.VCApiIssuanceService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.MessageSource;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebMvcTest(VCApiController.class)
@TestPropertySource(properties = "mosip.certify.vc-api.enabled=true")
public class VCApiControllerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private VCApiIssuanceService vcApiIssuanceService;

    @MockBean
    private ParsedAccessToken parsedAccessToken;

    @MockBean
    private MessageSource messageSource;

    @Test
    public void issueCredential_returnsVerifiableCredential() throws Exception {
        VcApiIssueRequest request = new VcApiIssueRequest();
        request.setCredentialSubject(Map.of("id", "did:example:holder", "fullName", "Jane Doe"));
        VcApiIssueOptions options = new VcApiIssueOptions();
        options.setCredentialConfigurationId("my-credential");
        request.setOptions(options);

        VcApiIssueResponse response = new VcApiIssueResponse();
        Map<String, Object> vc = new LinkedHashMap<>();
        vc.put("type", java.util.List.of("VerifiableCredential"));
        response.setVerifiableCredential(vc);
        Mockito.when(vcApiIssuanceService.issue(Mockito.any())).thenReturn(response);

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verifiableCredential.type").isArray());
    }

    @Test
    public void issueCredential_withMissingCredentialSubject_thenFail() throws Exception {
        VcApiIssueRequest request = new VcApiIssueRequest();
        VcApiIssueOptions options = new VcApiIssueOptions();
        options.setCredentialConfigurationId("my-credential");
        request.setOptions(options);

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(VCIErrorConstants.INVALID_REQUEST));
    }

    @Test
    public void issueCredential_withMissingOptions_thenFail() throws Exception {
        VcApiIssueRequest request = new VcApiIssueRequest();
        request.setCredentialSubject(Map.of("fullName", "Jane Doe"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(VCIErrorConstants.INVALID_REQUEST));
    }

    @Test
    public void issueCredential_withBlankCredentialConfigurationId_thenFail() throws Exception {
        VcApiIssueRequest request = new VcApiIssueRequest();
        request.setCredentialSubject(Map.of("fullName", "Jane Doe"));
        VcApiIssueOptions options = new VcApiIssueOptions();
        options.setCredentialConfigurationId("  ");
        request.setOptions(options);

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(VCIErrorConstants.INVALID_REQUEST));
    }

    @Test
    public void issueCredential_whenServiceThrowsCertifyException_thenFail() throws Exception {
        VcApiIssueRequest request = new VcApiIssueRequest();
        request.setCredentialSubject(Map.of("fullName", "Jane Doe"));
        VcApiIssueOptions options = new VcApiIssueOptions();
        options.setCredentialConfigurationId("unknown-config");
        request.setOptions(options);

        Mockito.when(vcApiIssuanceService.issue(Mockito.any()))
                .thenThrow(new CertifyException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, "Config not found"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value(ErrorConstants.CONFIG_NOT_FOUND_BY_ID));
    }

    @Test
    public void issueCredential_whenServiceThrowsUnsupportedFormat_thenFail() throws Exception {
        VcApiIssueRequest request = new VcApiIssueRequest();
        request.setCredentialSubject(Map.of("fullName", "Jane Doe"));
        VcApiIssueOptions options = new VcApiIssueOptions();
        options.setCredentialConfigurationId("sdjwt-config");
        request.setOptions(options);

        Mockito.when(vcApiIssuanceService.issue(Mockito.any()))
                .thenThrow(new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT,
                        "VC API v1 supports only ldp_vc credential format"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT));
    }
}
