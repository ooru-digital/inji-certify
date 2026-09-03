package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.JwksService;
import io.mosip.certify.core.spi.VCIssuanceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
public class WellKnownController {

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @Autowired
    private VCIssuanceService vcIssuanceService;

    @Autowired
    private JwksService jwksService;

    /**
     * Default issuer metadata (backward compatible). Inji Wallet concatenates
     * {@code credential_issuer_host + /.well-known/openid-credential-issuer}.
     */
    @GetMapping(value = "/.well-known/openid-credential-issuer", produces = "application/json")
    public CredentialIssuerMetadataDTO getCredentialIssuerMetadata(
            @RequestParam(name = "version", required = false, defaultValue = "latest") String version) {
        return credentialConfigurationService.fetchCredentialIssuerMetadata(null, version);
    }

    /**
     * Per-issuer OID4VCI metadata. Wallet host is {@code {domain}/{issuerId}}, so this is
     * {@code GET /{issuerId}/.well-known/openid-credential-issuer}.
     */
    @GetMapping(value = "/{issuerId}/.well-known/openid-credential-issuer", produces = "application/json")
    public CredentialIssuerMetadataDTO getIssuerCredentialIssuerMetadata(
            @PathVariable String issuerId,
            @RequestParam(name = "version", required = false, defaultValue = "latest") String version) {
        return credentialConfigurationService.fetchCredentialIssuerMetadata(issuerId, version);
    }

    @GetMapping(value = "/.well-known/did.json", produces = "application/json")
    public Map<String, Object> getDIDDocument(
            @RequestParam(value = "issuerId", required = false) String issuerId) {
        return vcIssuanceService.getDIDDocument(issuerId);
    }

    /**
     * Certify fetch endpoint for per-issuer DID documents.
     * {@code didUrl} is client-provided at onboard (e.g. {@code did:web:did.credissuer.com:iiitb});
     * clients host the returned JSON for did:web resolution.
     */
    @GetMapping(value = "/issuers/{issuerId}/did.json", produces = "application/json")
    public Map<String, Object> getIssuerDIDDocument(@PathVariable String issuerId) {
        return vcIssuanceService.getDIDDocument(issuerId);
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = "application/json")
    public ResponseEntity<Map<String, Object>> getJwks(
            @RequestParam(value = "issuerId", required = false) String issuerId) {
        try {
            Map<String, Object> response = jwksService.getJwks();

            if (response != null && response.containsKey("keys")) {
                return ResponseEntity.ok(response);
            } else {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("keys", Collections.emptyList());
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(errorResponse);
            }

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("keys", Collections.emptyList());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(errorResponse);
        }
    }
}
