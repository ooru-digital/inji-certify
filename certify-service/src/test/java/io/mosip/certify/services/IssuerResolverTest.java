package io.mosip.certify.services;

import io.mosip.certify.config.IssuerContext;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.IssuerConstants;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.repository.IssuerRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class IssuerResolverTest {

    @Mock
    private IssuerRepository issuerRepository;
    @Mock
    private CredentialConfigRepository credentialConfigRepository;
    @Mock
    private IssuerContext issuerContext;
    @InjectMocks
    private IssuerResolver issuerResolver;

    private Issuer defaultIssuer;
    private Issuer iiitb;

    @Before
    public void setUp() {
        defaultIssuer = issuer("default");
        iiitb = issuer("iiitb-ac");
        when(issuerRepository.findById("default")).thenReturn(Optional.of(defaultIssuer));
        when(issuerRepository.findById("iiitb-ac")).thenReturn(Optional.of(iiitb));
    }

    @Test
    public void resolve_blankIssuerId_matchesScopeToOnboardedIssuer() {
        CredentialConfig config = new CredentialConfig();
        config.setIssuerId("iiitb-ac");
        config.setScope("mock_identity_vc_ldp");
        when(credentialConfigRepository.findByScopeAndStatus("mock_identity_vc_ldp", Constants.ACTIVE))
                .thenReturn(List.of(config));

        Issuer resolved = issuerResolver.resolve(null, "openid mock_identity_vc_ldp");

        assertEquals("iiitb-ac", resolved.getIssuerId());
    }

    @Test
    public void resolve_blankIssuerIdAndUnknownScope_fallsBackToDefault() {
        when(credentialConfigRepository.findByScopeAndStatus("unknown_scope", Constants.ACTIVE))
                .thenReturn(List.of());

        Issuer resolved = issuerResolver.resolve(null, "unknown_scope");

        assertEquals(IssuerConstants.DEFAULT_ISSUER_ID, resolved.getIssuerId());
    }

    @Test
    public void resolve_explicitIssuerId_ignoresScope() {
        Issuer resolved = issuerResolver.resolve("iiitb-ac", "some_other_scope");

        assertEquals("iiitb-ac", resolved.getIssuerId());
    }

    private static Issuer issuer(String id) {
        Issuer issuer = new Issuer();
        issuer.setIssuerId(id);
        issuer.setStatus(Constants.ACTIVE);
        return issuer;
    }
}
