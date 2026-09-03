package io.mosip.certify.services;

import io.mosip.certify.config.IssuerContext;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.IssuerConstants;
import io.mosip.certify.core.dto.CredentialProof;
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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class IssuerResolverTest {

    private static final String CR_ORG_AUD = "https://host/certify/cr-org";
    private static final String SHARED_SCOPE = "mock_identity_vc_ldp";

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
    private Issuer crOrg;

    @Before
    public void setUp() {
        defaultIssuer = issuer("default");
        iiitb = issuer("iiitb-ac");
        crOrg = issuer("cr-org");
        crOrg.setCredentialIssuerUrl(CR_ORG_AUD);
        crOrg.setIdentifier(CR_ORG_AUD);
        lenient().when(issuerRepository.findById("default")).thenReturn(Optional.of(defaultIssuer));
        lenient().when(issuerRepository.findById("iiitb-ac")).thenReturn(Optional.of(iiitb));
        lenient().when(issuerRepository.findById("cr-org")).thenReturn(Optional.of(crOrg));
    }

    @Test
    public void resolve_blankIssuerId_matchesScopeToOnboardedIssuer() {
        CredentialConfig config = new CredentialConfig();
        config.setIssuerId("iiitb-ac");
        config.setScope(SHARED_SCOPE);
        when(credentialConfigRepository.findByScopeAndStatus(SHARED_SCOPE, Constants.ACTIVE))
                .thenReturn(List.of(config));

        Issuer resolved = issuerResolver.resolve(null, "openid " + SHARED_SCOPE);

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

    @Test
    public void resolve_sharedScope_proofAudSelectsIssuer() {
        when(issuerRepository.findByCredentialIssuerUrlAndStatus(CR_ORG_AUD, Constants.ACTIVE))
                .thenReturn(Optional.of(crOrg));

        Issuer resolved = issuerResolver.resolve(null, "openid " + SHARED_SCOPE, jwtProofWithAud(CR_ORG_AUD));

        assertEquals("cr-org", resolved.getIssuerId());
    }

    @Test
    public void resolve_sharedScope_proofAudPathSegmentSelectsIssuer() {
        when(issuerRepository.findByIssuerIdAndStatus("cr-org", Constants.ACTIVE))
                .thenReturn(Optional.of(crOrg));

        Issuer resolved = issuerResolver.resolve(null, SHARED_SCOPE, jwtProofWithAud(CR_ORG_AUD + "/"));

        assertEquals("cr-org", resolved.getIssuerId());
    }

    @Test
    public void resolve_sameScopeMultipleTemplatesOneIssuer_usesThatIssuer() {
        CredentialConfig vedax = config("LASTT-HM3WWA", SHARED_SCOPE);
        CredentialConfig transcript = config("LASTT-HM3WWA", SHARED_SCOPE);
        when(credentialConfigRepository.findByScopeAndStatus(SHARED_SCOPE, Constants.ACTIVE))
                .thenReturn(List.of(vedax, transcript));
        Issuer lastt = issuer("LASTT-HM3WWA");
        when(issuerRepository.findById("LASTT-HM3WWA")).thenReturn(Optional.of(lastt));

        Issuer resolved = issuerResolver.resolve(null, SHARED_SCOPE);

        assertEquals("LASTT-HM3WWA", resolved.getIssuerId());
    }

    @Test
    public void resolve_sharedScopeAcrossIssuersWithoutAud_doesNotPickRandomIssuer() {
        when(credentialConfigRepository.findByScopeAndStatus(SHARED_SCOPE, Constants.ACTIVE))
                .thenReturn(List.of(config("iiitb-ac", SHARED_SCOPE), config("cr-org", SHARED_SCOPE)));

        Issuer resolved = issuerResolver.resolve(null, SHARED_SCOPE);

        assertEquals(IssuerConstants.DEFAULT_ISSUER_ID, resolved.getIssuerId());
    }

    @Test
    public void resolve_sharedScopeAcrossIssuersUnknownAud_doesNotPickRandomIssuer() {
        when(credentialConfigRepository.findByScopeAndStatus(SHARED_SCOPE, Constants.ACTIVE))
                .thenReturn(List.of(config("iiitb-ac", SHARED_SCOPE), config("cr-org", SHARED_SCOPE)));

        Issuer resolved = issuerResolver.resolve(null, SHARED_SCOPE,
                jwtProofWithAud("https://host/certify/unknown-org"));

        assertEquals(IssuerConstants.DEFAULT_ISSUER_ID, resolved.getIssuerId());
    }

    @Test
    public void resolve_explicitIssuerId_ignoresProofAud() {
        Issuer resolved = issuerResolver.resolve("iiitb-ac", SHARED_SCOPE, jwtProofWithAud(CR_ORG_AUD));

        assertEquals("iiitb-ac", resolved.getIssuerId());
    }

    private static Issuer issuer(String id) {
        Issuer issuer = new Issuer();
        issuer.setIssuerId(id);
        issuer.setStatus(Constants.ACTIVE);
        return issuer;
    }

    private static CredentialConfig config(String issuerId, String scope) {
        CredentialConfig config = new CredentialConfig();
        config.setIssuerId(issuerId);
        config.setScope(scope);
        return config;
    }

    private static CredentialProof jwtProofWithAud(String aud) {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("{\"aud\":\"" + aud + "\"}").getBytes(StandardCharsets.UTF_8));
        CredentialProof proof = new CredentialProof();
        proof.setProof_type("jwt");
        proof.setJwt(header + "." + payload + ".");
        return proof;
    }
}
