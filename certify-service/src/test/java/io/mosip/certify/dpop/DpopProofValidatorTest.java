package io.mosip.certify.dpop;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.util.CommonUtil;

import static org.junit.jupiter.api.Assertions.*;

class DpopProofValidatorTest {

    private static final String DOMAIN_URL = "https://certify.example.com";
    private static final String REQUEST_URI = "/v1/certify/issuance/credential";
    private static final String ACCESS_TOKEN = "an.access.token";

    private DpopProofValidator validator;
    private MockHttpServletRequest request;
    private ECKey walletKey;
    private String walletJkt;

    @BeforeEach
    void setUp() throws Exception {
        validator = new DpopProofValidator();
        ReflectionTestUtils.setField(validator, "domainUrl", DOMAIN_URL);
        ReflectionTestUtils.setField(validator, "allowedAlgorithms", Arrays.asList("ES256", "RS256", "PS256"));
        ReflectionTestUtils.setField(validator, "proofMaxAgeSeconds", 60L);
        ReflectionTestUtils.setField(validator, "maxClockSkewSeconds", 10L);
        ReflectionTestUtils.setField(validator, "cacheManager",
                new ConcurrentMapCacheManager(DpopProofValidator.DPOP_JTI_CACHE));
        ReflectionTestUtils.setField(validator, "cacheType", "simple");

        request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setRequestURI(REQUEST_URI);

        walletKey = new ECKeyGenerator(Curve.P_256).keyID("wallet").generate();
        walletJkt = walletKey.toPublicJWK().computeThumbprint().toString();
    }

    // ---------- happy path ----------

    @Test
    void validProof_shouldReturnThumbprintAndJti() throws Exception {
        String proof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);

        DpopProofValidator.ValidatedProof result =
                validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request);

        assertEquals(walletJkt, result.jkt());
        assertEquals("jti-1", result.jti());
    }

    @Test
    void htuWithQueryAndFragment_shouldStillMatch() throws Exception {
        // RFC 9449 §4.3: htu is compared ignoring query and fragment.
        JWTClaimsSet claims = defaultClaims()
                .claim("htu", DOMAIN_URL + REQUEST_URI + "?x=1#frag").build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);

        assertEquals(walletJkt, validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request).jkt());
    }

    @Test
    void defaultHttpsPort_shouldNormalizeAway() throws Exception {
        JWTClaimsSet claims = defaultClaims()
                .claim("htu", "https://certify.example.com:443" + REQUEST_URI).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);

        assertEquals(walletJkt, validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request).jkt());
    }

    // ---------- structure ----------

    @Test
    void missingHeader_shouldFail() {
        assertInvalid(() -> validator.validate(null, ACCESS_TOKEN, boundClaims(walletJkt), request), "missing");
    }

    @Test
    void multipleProofs_shouldFail() throws Exception {
        String proof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof + "," + proof, ACCESS_TOKEN, boundClaims(walletJkt), request),
                "Exactly one");
    }

    @Test
    void notAJws_shouldFail() {
        assertInvalid(() -> validator.validate("not-a-jwt", ACCESS_TOKEN, boundClaims(walletJkt), request),
                "well-formed");
    }

    @Test
    void wrongTyp_shouldFail() throws Exception {
        String proof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "JWT", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "typ");
    }

    @Test
    void disallowedAlgorithm_shouldFail() throws Exception {
        ReflectionTestUtils.setField(validator, "allowedAlgorithms", Arrays.asList("RS256"));
        String proof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "algorithm");
    }

    @Test
    void missingJwk_shouldFail() throws Exception {
        String proof = signProof(walletKey, defaultClaims().build(), null, "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "jwk");
    }

    @Test
    void jwkWithPrivateMaterial_shouldBeRejected() throws Exception {
        // A proof must only ever embed the public half. Nimbus refuses to *build* such a
        // header (JWSHeader.Builder.jwk() rejects a private JWK), so the header is crafted
        // by hand here - which is what a hostile client would have to do anyway.
        String validProof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(),
                "dpop+jwt", JWSAlgorithm.ES256);
        String[] parts = validProof.split("\\.");
        String headerJson = "{\"alg\":\"ES256\",\"typ\":\"dpop+jwt\",\"jwk\":" + walletKey.toJSONString() + "}";
        String crafted = com.nimbusds.jose.util.Base64URL.encode(headerJson) + "." + parts[1] + "." + parts[2];

        CertifyException e = assertThrows(CertifyException.class,
                () -> validator.validate(crafted, ACCESS_TOKEN, boundClaims(walletJkt), request));
        assertEquals(ErrorConstants.INVALID_DPOP_PROOF, e.getErrorCode());
    }

    @Test
    void signatureFromAnotherKey_shouldFail() throws Exception {
        ECKey attackerKey = new ECKeyGenerator(Curve.P_256).keyID("attacker").generate();
        // Signed by the attacker, but advertising the wallet's public key.
        String proof = signProof(attackerKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "signature");
    }

    // ---------- request binding ----------

    @Test
    void htmMismatch_shouldFail() throws Exception {
        JWTClaimsSet claims = defaultClaims().claim("htm", "GET").build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "htm");
    }

    @Test
    void htuMismatch_shouldFail() throws Exception {
        JWTClaimsSet claims = defaultClaims()
                .claim("htu", "https://evil.example.com" + REQUEST_URI).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "htu");
    }

    @Test
    void proofForAnotherEndpoint_shouldFail() throws Exception {
        // A proof minted for eSignet's /token must not be replayable at Certify.
        JWTClaimsSet claims = defaultClaims()
                .claim("htu", "https://esignet.example.com/v1/esignet/oauth/v2/token").build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "htu");
    }

    // ---------- freshness ----------

    @Test
    void staleProof_shouldFail() throws Exception {
        JWTClaimsSet claims = defaultClaims()
                .issueTime(Date.from(Instant.now().minusSeconds(600))).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "expired");
    }

    @Test
    void proofFromTheFuture_shouldFail() throws Exception {
        JWTClaimsSet claims = defaultClaims()
                .issueTime(Date.from(Instant.now().plusSeconds(600))).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "future");
    }

    @Test
    void withinClockSkew_shouldPass() throws Exception {
        JWTClaimsSet claims = defaultClaims()
                .issueTime(Date.from(Instant.now().plusSeconds(5))).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertEquals(walletJkt, validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request).jkt());
    }

    @Test
    void missingIat_shouldFail() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID("jti-1")
                .claim("htm", "POST")
                .claim("htu", DOMAIN_URL + REQUEST_URI)
                .claim("ath", CommonUtil.generateB64EncodedHash(CommonUtil.ALGO_SHA_256, ACCESS_TOKEN))
                .build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "iat");
    }

    // ---------- token binding ----------

    @Test
    void athForADifferentToken_shouldFail() throws Exception {
        JWTClaimsSet claims = defaultClaims()
                .claim("ath", CommonUtil.generateB64EncodedHash(CommonUtil.ALGO_SHA_256, "some.other.token")).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "ath");
    }

    @Test
    void truncatedOidcAtHash_shouldNotBeAccepted() throws Exception {
        // Guards the CommonUtil split: at_hash keeps 128 bits, ath keeps the full digest.
        JWTClaimsSet claims = defaultClaims()
                .claim("ath", CommonUtil.generateOIDCAtHash(ACCESS_TOKEN)).build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "ath");
    }

    @Test
    void unboundAccessToken_shouldFail() throws Exception {
        String proof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, Map.of("sub", "user"), request), "not DPoP-bound");
    }

    @Test
    void thumbprintMismatch_shouldFail() throws Exception {
        // The wallet's own key, but a token bound to somebody else's.
        ECKey otherKey = new ECKeyGenerator(Curve.P_256).generate();
        String otherJkt = otherKey.toPublicJWK().computeThumbprint().toString();
        String proof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(otherJkt), request),
                "does not match the access token binding");
    }

    @Test
    void missingJti_shouldFail() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issueTime(new Date())
                .claim("htm", "POST")
                .claim("htu", DOMAIN_URL + REQUEST_URI)
                .claim("ath", CommonUtil.generateB64EncodedHash(CommonUtil.ALGO_SHA_256, ACCESS_TOKEN))
                .build();
        String proof = signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request), "jti");
    }

    // ---------- replay ----------

    @Test
    void replayedProof_shouldBeRejected() throws Exception {
        String proof = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);

        assertEquals(walletJkt, validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request).jkt());
        assertInvalid(() -> validator.validate(proof, ACCESS_TOKEN, boundClaims(walletJkt), request),
                "already been used");
    }

    @Test
    void rejectedProof_shouldNotBurnItsJti() throws Exception {
        // The replay check is the last thing validate() does, so a proof turned away on any
        // earlier rule must leave its jti spendable - otherwise one malformed request would
        // lock the wallet out of retrying with the same jti.
        JWTClaimsSet bad = defaultClaims().claim("htm", "GET").build();
        assertInvalid(() -> validator.validate(
                signProofUnchecked(bad), ACCESS_TOKEN, boundClaims(walletJkt), request), "htm");

        String good = signProof(walletKey, defaultClaims().build(), walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        assertEquals("jti-1", validator.validate(good, ACCESS_TOKEN, boundClaims(walletJkt), request).jti());
    }

    @Test
    void distinctJtis_shouldAllBeAccepted() {
        for (int i = 0; i < 25; i++) {
            assertFalse(validator.checkAndMarkJti("jti-" + i));
        }
    }

    @Test
    void missingCache_shouldFailClosedRatherThanSkipTheCheck() {
        // A cache manager that knows nothing about dpopJti - the exact situation when the
        // cache name is left out of mosip.certify.cache.names.
        ReflectionTestUtils.setField(validator, "cacheManager",
                new ConcurrentMapCacheManager("someOtherCache"));

        CertifyException e = assertThrows(CertifyException.class,
                () -> validator.checkAndMarkJti("jti-1"));
        assertEquals(ErrorConstants.INVALID_DPOP_PROOF, e.getErrorCode());
        assertTrue(e.getMessage().contains("mosip.certify.cache.names"),
                "the error should name the property that needs fixing");
    }

    @Test
    void concurrentReplays_onlyOneShouldWin() throws Exception {
        int threads = 16;
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        List<Thread> workers = new ArrayList<>();

        for (int i = 0; i < threads; i++) {
            Thread t = new Thread(() -> {
                try {
                    start.await();
                    if (!validator.checkAndMarkJti("racy-jti")) {
                        accepted.incrementAndGet();
                    }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            });
            workers.add(t);
            t.start();
        }
        start.countDown();
        for (Thread t : workers) {
            t.join();
        }

        // putIfAbsent is atomic; a get-then-put would let several threads through here.
        assertEquals(1, accepted.get(), "exactly one concurrent use of a jti may succeed");
    }

    // ---------- helpers ----------

    private JWTClaimsSet.Builder defaultClaims() {
        return new JWTClaimsSet.Builder()
                .jwtID("jti-1")
                .issueTime(new Date())
                .claim("htm", "POST")
                .claim("htu", DOMAIN_URL + REQUEST_URI)
                .claim("ath", CommonUtil.generateB64EncodedHash(CommonUtil.ALGO_SHA_256, ACCESS_TOKEN));
    }

    private Map<String, Object> boundClaims(String jkt) {
        return Map.of("cnf", Map.of("jkt", jkt));
    }

    private String signProof(ECKey signingKey, JWTClaimsSet claims, com.nimbusds.jose.jwk.JWK embeddedJwk,
                             String typ, JWSAlgorithm alg) throws Exception {
        JWSHeader.Builder header = new JWSHeader.Builder(alg).type(new JOSEObjectType(typ));
        if (embeddedJwk != null) {
            header.jwk(embeddedJwk);
        }
        SignedJWT jwt = new SignedJWT(header.build(), claims);
        jwt.sign(new ECDSASigner(signingKey));
        return jwt.serialize();
    }

    /** signProof without the checked exception, for use inside a lambda. */
    private String signProofUnchecked(JWTClaimsSet claims) {
        try {
            return signProof(walletKey, claims, walletKey.toPublicJWK(), "dpop+jwt", JWSAlgorithm.ES256);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private void assertInvalid(Runnable action, String expectedMessageFragment) {
        CertifyException e = assertThrows(CertifyException.class, action::run);
        assertEquals(ErrorConstants.INVALID_DPOP_PROOF, e.getErrorCode());
        assertTrue(e.getMessage().toLowerCase().contains(expectedMessageFragment.toLowerCase()),
                "expected message to contain '" + expectedMessageFragment + "' but was: " + e.getMessage());
    }
}
