package io.mosip.certify.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.dto.VCApiIssueRequest;
import io.mosip.certify.core.dto.VCApiIssueResponse;
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
import java.util.List;
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
        VCApiIssueRequest request = validRequest();

        VCApiIssueResponse response = new VCApiIssueResponse();
        Map<String, Object> vc = new LinkedHashMap<>();
        vc.put("type", List.of("VerifiableCredential", "FarmerCredential"));
        response.setVerifiableCredential(vc);
        Mockito.when(vcApiIssuanceService.issue(Mockito.any(), Mockito.eq("my-credential"))).thenReturn(response);

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "my-credential")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.verifiableCredential.type").isArray());
    }

    @Test
    public void issueCredential_withMissingCredential_thenFail() throws Exception {
        VCApiIssueRequest request = new VCApiIssueRequest();

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "my-credential")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(VCIErrorConstants.INVALID_REQUEST));
    }

    @Test
    public void issueCredential_withMissingConfigHeader_thenFail() throws Exception {
        mockMvc.perform(post("/vc-api/credentials/issue")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(VCIErrorConstants.INVALID_REQUEST));
    }

    @Test
    public void issueCredential_withBlankConfigHeader_thenFail() throws Exception {
        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "  ")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(ErrorConstants.INVALID_REQUEST));
    }

    @Test
    public void issueCredential_whenServiceThrowsCertifyException_thenFail() throws Exception {
        Mockito.when(vcApiIssuanceService.issue(Mockito.any(), Mockito.eq("unknown-config")))
                .thenThrow(new CertifyException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, "Config not found"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "unknown-config")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value(ErrorConstants.CONFIG_NOT_FOUND_BY_ID));
    }

    @Test
    public void issueCredential_whenServiceThrowsUnsupportedFormat_thenFail() throws Exception {
        Mockito.when(vcApiIssuanceService.issue(Mockito.any(), Mockito.eq("sdjwt-config")))
                .thenThrow(new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT,
                        "VC API supports only ldp_vc credential format"));

        mockMvc.perform(post("/vc-api/credentials/issue")
                        .header(VCApiController.CREDENTIAL_CONFIGURATION_ID_HEADER, "sdjwt-config")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validRequest())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT));
    }

    private VCApiIssueRequest validRequest() {
        VCApiIssueRequest request = new VCApiIssueRequest();
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("@context", List.of(VCDM2Constants.URL));
        credential.put("type", List.of("VerifiableCredential", "FarmerCredential"));
        credential.put("issuer", "did:web:example.issuer");
        credential.put("validFrom", "2026-01-01T00:00:00.000Z");
        credential.put("credentialSubject", Map.of("id", "did:example:holder", "fullName", "Jane Doe"));
        request.setCredential(credential);
        return request;
    }
}
