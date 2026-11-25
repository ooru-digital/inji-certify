package io.mosip.certify.core.spi;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.certify.core.dto.*;

public interface CredentialConfigurationService {

    CredentialConfigResponse addCredentialConfiguration(CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException;

    CredentialConfigurationDTO getCredentialConfigurationById(String id) throws JsonProcessingException;

    java.util.List<CredentialConfigurationDTO> listCredentialConfigurations(String issuerId) throws JsonProcessingException;

    CredentialConfigResponse updateCredentialConfiguration(String id, CredentialConfigurationDTO credentialConfigurationDTO) throws JsonProcessingException;

    String deleteCredentialConfigurationById(String id);

    /** All active configurations of the issuer; used when issuing. Blank issuerId means the default issuer. */
    CredentialIssuerMetadataDTO fetchCredentialIssuerMetadata(String issuerId);

    /** Metadata advertised to wallets, restricted to the configured well-known formats. */
    CredentialIssuerMetadataDTO fetchWellKnownMetadata(String issuerId);
}
