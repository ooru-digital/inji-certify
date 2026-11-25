/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.mdoc;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.IssuerConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.utils.KeyManagerAppIdUtil;
import io.mosip.kernel.core.keymanager.model.CertificateEntry;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.dto.SignatureCertificate;
import io.mosip.kernel.keymanagerservice.dto.UploadCertificateRequestDto;
import io.mosip.kernel.keymanagerservice.entity.KeyPolicy;
import io.mosip.kernel.keymanagerservice.repository.KeyPolicyRepository;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class MdocPkiServiceTest {

    @Mock
    private KeymanagerService keymanagerService;

    @Mock
    private KeyPolicyRepository keyPolicyRepository;

    @InjectMocks
    private MdocPkiService mdocPkiService;

    private KeyPair iacaKeyPair;
    private KeyPair dsKeyPair;

    @BeforeClass
    public static void addProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Before
    public void setUp() throws Exception {
        ReflectionTestUtils.setField(mdocPkiService, "iacaValidityDays", 7300);
        ReflectionTestUtils.setField(mdocPkiService, "iacaPreExpireDays", 90);
        ReflectionTestUtils.setField(mdocPkiService, "dsValidityDays", 457);
        ReflectionTestUtils.setField(mdocPkiService, "dsPreExpireDays", 60);
        ReflectionTestUtils.setField(mdocPkiService, "iacaCnPrefix", "IACA-");
        ReflectionTestUtils.setField(mdocPkiService, "dsCnPrefix", "DS-");
        ReflectionTestUtils.setField(mdocPkiService, "organization", "MOSIP");
        ReflectionTestUtils.setField(mdocPkiService, "organizationalUnit", "CERTIFY");
        ReflectionTestUtils.setField(mdocPkiService, "country", "IN");
        ReflectionTestUtils.setField(mdocPkiService, "state", "KA");
        ReflectionTestUtils.setField(mdocPkiService, "location", "BLR");
        ReflectionTestUtils.setField(mdocPkiService, "issuerAlternativeNameEmail", "iaca@example.com");
        ReflectionTestUtils.setField(mdocPkiService, "issuerAlternativeNameUri", "https://example.com/iaca");
        ReflectionTestUtils.setField(mdocPkiService, "crlDistributionPointUri", "https://example.com/crl/iaca.crl");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        iacaKeyPair = generator.generateKeyPair();
        dsKeyPair = generator.generateKeyPair();

        when(keyPolicyRepository.findByApplicationId(anyString())).thenReturn(Optional.empty());
        when(keyPolicyRepository.save(any(KeyPolicy.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(keymanagerService.generateECSignKey(eq("certificate"), any(KeyPairGenerateRequestDto.class)))
                .thenReturn(new KeyPairGenerateResponseDto());
    }

    @Test
    public void provision_GeneratesKeysUploadsIacaAndDsCerts() throws Exception {
        stubSignatureMaterial("CERTIFY_IACA_ACME", iacaKeyPair);
        stubSignatureMaterial("CERTIFY_DS_ACME", dsKeyPair);

        MdocPkiRefs refs = mdocPkiService.provision("acme");

        assertEquals("CERTIFY_IACA_ACME", refs.iacaAppId());
        assertEquals(Constants.EC_SECP256R1_SIGN, refs.iacaRefId());
        assertEquals("CERTIFY_DS_ACME", refs.dsAppId());
        assertEquals(Constants.EC_SECP256R1_SIGN, refs.dsRefId());

        ArgumentCaptor<KeyPolicy> policyCaptor = ArgumentCaptor.forClass(KeyPolicy.class);
        verify(keyPolicyRepository, times(2)).save(policyCaptor.capture());
        assertEquals(7300, policyCaptor.getAllValues().get(0).getValidityInDays());
        assertEquals(457, policyCaptor.getAllValues().get(1).getValidityInDays());

        ArgumentCaptor<UploadCertificateRequestDto> uploadCaptor =
                ArgumentCaptor.forClass(UploadCertificateRequestDto.class);
        verify(keymanagerService, times(2)).uploadCertificate(uploadCaptor.capture());

        UploadCertificateRequestDto iacaUpload = uploadCaptor.getAllValues().get(0);
        UploadCertificateRequestDto dsUpload = uploadCaptor.getAllValues().get(1);
        assertEquals("CERTIFY_IACA_ACME", iacaUpload.getApplicationId());
        assertEquals("CERTIFY_DS_ACME", dsUpload.getApplicationId());

        X509Certificate iacaCert = parsePem(iacaUpload.getCertificateData());
        X509Certificate dsCert = parsePem(dsUpload.getCertificateData());
        assertEquals(0, iacaCert.getBasicConstraints());
        assertEquals(-1, dsCert.getBasicConstraints());
        assertTrue(iacaCert.getSubjectX500Principal().getName().contains("IACA-acme"));
        assertTrue(dsCert.getSubjectX500Principal().getName().contains("DS-acme"));
        assertEquals(iacaCert.getSubjectX500Principal(), dsCert.getIssuerX500Principal());
        dsCert.verify(iacaKeyPair.getPublic());
        assertTrue(iacaCert.getKeyUsage()[5]);
        assertTrue(iacaCert.getKeyUsage()[6]);
        assertFalse(iacaCert.getKeyUsage()[0]);
        assertNotNull(iacaCert.getExtensionValue(Extension.subjectKeyIdentifier.getId()));
        assertNotNull(iacaCert.getExtensionValue(Extension.authorityKeyIdentifier.getId()));
        assertNotNull(iacaCert.getExtensionValue(Extension.issuerAlternativeName.getId()));
        assertNotNull(dsCert.getExtensionValue(Extension.authorityKeyIdentifier.getId()));
        assertNotNull(dsCert.getExtensionValue(Extension.subjectKeyIdentifier.getId()));
        assertNotNull(dsCert.getExtensionValue(Extension.cRLDistributionPoints.getId()));
        assertNotNull(dsCert.getExtensionValue(Extension.issuerAlternativeName.getId()));
        assertEquals(List.of("1.0.18013.5.1.2"), dsCert.getExtendedKeyUsage());
        assertTrue(dsCert.getCriticalExtensionOIDs().contains(Extension.extendedKeyUsage.getId()));
        assertTrue(MdocCertificateFactory.hasIsoIacaProfile(iacaCert));
        assertTrue(MdocCertificateFactory.hasIsoDsProfile(dsCert));

        long iacaDays = ChronoUnit.DAYS.between(
                iacaCert.getNotBefore().toInstant(), iacaCert.getNotAfter().toInstant());
        long dsDays = ChronoUnit.DAYS.between(
                dsCert.getNotBefore().toInstant(), dsCert.getNotAfter().toInstant());
        assertTrue(iacaDays >= 7290 && iacaDays <= 7310);
        assertTrue(dsDays >= 450 && dsDays <= 465);
    }

    @Test
    public void provision_LongIssuerId_UsesShortenedAppIds() throws Exception {
        String longIssuerId = "this-issuer-id-is-way-too-long-for-app";
        String expectedIacaAppId = KeyManagerAppIdUtil.buildAppId(IssuerConstants.IACA_APP_ID_PREFIX, longIssuerId);
        String expectedDsAppId = KeyManagerAppIdUtil.buildAppId(IssuerConstants.DS_APP_ID_PREFIX, longIssuerId);
        assertTrue(expectedIacaAppId.length() <= KeyManagerAppIdUtil.MAX_APP_ID_LENGTH);
        assertTrue(expectedDsAppId.length() <= KeyManagerAppIdUtil.MAX_APP_ID_LENGTH);

        stubSignatureMaterial(expectedIacaAppId, iacaKeyPair);
        stubSignatureMaterial(expectedDsAppId, dsKeyPair);

        MdocPkiRefs refs = mdocPkiService.provision(longIssuerId);

        assertEquals(expectedIacaAppId, refs.iacaAppId());
        assertEquals(expectedDsAppId, refs.dsAppId());
        verify(keymanagerService, times(2)).uploadCertificate(any());
        verify(keymanagerService, atLeast(2)).generateECSignKey(eq("certificate"), any());
    }

    @Test
    public void rotateDocumentSigner_ForceRegeneratesDsAndReuploads() throws Exception {
        Issuer issuer = new Issuer();
        issuer.setIssuerId("acme");
        issuer.setMdocIacaAppId("CERTIFY_IACA_ACME");
        issuer.setMdocIacaRefId(Constants.EC_SECP256R1_SIGN);
        issuer.setMdocDsAppId("CERTIFY_DS_ACME");
        issuer.setMdocDsRefId(Constants.EC_SECP256R1_SIGN);

        stubSignatureMaterial("CERTIFY_IACA_ACME", iacaKeyPair);
        stubSignatureMaterial("CERTIFY_DS_ACME", dsKeyPair);

        mdocPkiService.rotateDocumentSigner(issuer);

        ArgumentCaptor<KeyPairGenerateRequestDto> genCaptor = ArgumentCaptor.forClass(KeyPairGenerateRequestDto.class);
        verify(keymanagerService, atLeast(1)).generateECSignKey(eq("certificate"), genCaptor.capture());
        assertTrue(genCaptor.getAllValues().stream().anyMatch(req ->
                "CERTIFY_DS_ACME".equals(req.getApplicationId()) && Boolean.TRUE.equals(req.getForce())));

        ArgumentCaptor<UploadCertificateRequestDto> uploadCaptor =
                ArgumentCaptor.forClass(UploadCertificateRequestDto.class);
        verify(keymanagerService, times(1)).uploadCertificate(uploadCaptor.capture());
        assertEquals("CERTIFY_DS_ACME", uploadCaptor.getValue().getApplicationId());
    }

    @Test
    public void isDsRotationDue_NearExpiry_ReturnsTrue() throws Exception {
        Issuer issuer = new Issuer();
        issuer.setIssuerId("acme");
        issuer.setMdocDsAppId("CERTIFY_DS_ACME");
        issuer.setMdocDsRefId(Constants.EC_SECP256R1_SIGN);

        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        X509Certificate nearExpiry = MdocCertificateFactory.buildDsCertificate(
                iacaKeyPair.getPrivate(),
                iacaKeyPair.getPublic(),
                dsKeyPair.getPublic(),
                MdocCertificateFactory.toX500Name(buildTempIaca()),
                "DS-acme",
                "MOSIP",
                "CERTIFY",
                "IN",
                "KA",
                "BLR",
                now.minusDays(700),
                now.plusDays(10),
                BouncyCastleProvider.PROVIDER_NAME);

        KeyPairGenerateResponseDto response = new KeyPairGenerateResponseDto();
        response.setCertificate(MdocCertificateFactory.toPem(nearExpiry));
        when(keymanagerService.getCertificate(eq("CERTIFY_DS_ACME"), eq(Optional.of(Constants.EC_SECP256R1_SIGN))))
                .thenReturn(response);

        assertTrue(mdocPkiService.isDsRotationDue(issuer));
    }

    @Test
    public void isDsRotationDue_FarFromExpiry_ReturnsFalse() throws Exception {
        Issuer issuer = new Issuer();
        issuer.setIssuerId("acme");
        issuer.setMdocDsAppId("CERTIFY_DS_ACME");
        issuer.setMdocDsRefId(Constants.EC_SECP256R1_SIGN);

        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        X509Certificate fresh = MdocCertificateFactory.buildDsCertificate(
                iacaKeyPair.getPrivate(),
                iacaKeyPair.getPublic(),
                dsKeyPair.getPublic(),
                MdocCertificateFactory.toX500Name(buildTempIaca()),
                "DS-acme",
                "MOSIP",
                "CERTIFY",
                "IN",
                "KA",
                "BLR",
                now,
                now.plusDays(730),
                BouncyCastleProvider.PROVIDER_NAME);

        KeyPairGenerateResponseDto response = new KeyPairGenerateResponseDto();
        response.setCertificate(MdocCertificateFactory.toPem(fresh));
        when(keymanagerService.getCertificate(eq("CERTIFY_DS_ACME"), eq(Optional.of(Constants.EC_SECP256R1_SIGN))))
                .thenReturn(response);

        assertFalse(mdocPkiService.isDsRotationDue(issuer));
    }

    @Test
    public void ensureDocumentSignerCurrent_WhenDue_Rotates() throws Exception {
        Issuer issuer = new Issuer();
        issuer.setIssuerId("acme");
        issuer.setMdocIacaAppId("CERTIFY_IACA_ACME");
        issuer.setMdocIacaRefId(Constants.EC_SECP256R1_SIGN);
        issuer.setMdocDsAppId("CERTIFY_DS_ACME");
        issuer.setMdocDsRefId(Constants.EC_SECP256R1_SIGN);

        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        X509Certificate selfSignedIaca = buildTempIaca();
        X509Certificate nearExpiry = MdocCertificateFactory.buildDsCertificate(
                iacaKeyPair.getPrivate(),
                iacaKeyPair.getPublic(),
                dsKeyPair.getPublic(),
                MdocCertificateFactory.toX500Name(selfSignedIaca),
                "DS-acme",
                "MOSIP",
                "CERTIFY",
                "IN",
                "KA",
                "BLR",
                now.minusDays(700),
                now.plusDays(30),
                BouncyCastleProvider.PROVIDER_NAME);

        KeyPairGenerateResponseDto iacaResponse = new KeyPairGenerateResponseDto();
        iacaResponse.setCertificate(MdocCertificateFactory.toPem(selfSignedIaca));
        when(keymanagerService.getCertificate(eq("CERTIFY_IACA_ACME"), eq(Optional.of(Constants.EC_SECP256R1_SIGN))))
                .thenReturn(iacaResponse);

        KeyPairGenerateResponseDto getCertResponse = new KeyPairGenerateResponseDto();
        getCertResponse.setCertificate(MdocCertificateFactory.toPem(nearExpiry));
        when(keymanagerService.getCertificate(eq("CERTIFY_DS_ACME"), eq(Optional.of(Constants.EC_SECP256R1_SIGN))))
                .thenReturn(getCertResponse);

        stubSignatureMaterial("CERTIFY_IACA_ACME", iacaKeyPair);
        stubSignatureMaterial("CERTIFY_DS_ACME", dsKeyPair);

        org.mockito.Mockito.doAnswer(invocation -> {
            UploadCertificateRequestDto req = invocation.getArgument(0);
            KeyPairGenerateResponseDto updated = new KeyPairGenerateResponseDto();
            updated.setCertificate(req.getCertificateData());
            when(keymanagerService.getCertificate(eq(req.getApplicationId()),
                    eq(Optional.of(req.getReferenceId())))).thenReturn(updated);
            return null;
        }).when(keymanagerService).uploadCertificate(any(UploadCertificateRequestDto.class));

        mdocPkiService.ensureDocumentSignerCurrent(issuer);

        verify(keymanagerService, atLeast(1)).generateECSignKey(eq("certificate"), any());
        verify(keymanagerService, atLeast(1)).uploadCertificate(any());
    }

    @Test
    public void ensureDocumentSignerCurrent_WhenNotDue_DoesNotRotate() throws Exception {
        Issuer issuer = new Issuer();
        issuer.setIssuerId("acme");
        issuer.setMdocDsAppId("CERTIFY_DS_ACME");
        issuer.setMdocDsRefId(Constants.EC_SECP256R1_SIGN);

        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        X509Certificate fresh = MdocCertificateFactory.buildDsCertificate(
                iacaKeyPair.getPrivate(),
                iacaKeyPair.getPublic(),
                dsKeyPair.getPublic(),
                MdocCertificateFactory.toX500Name(buildTempIaca()),
                "DS-acme",
                "MOSIP",
                "CERTIFY",
                "IN",
                "KA",
                "BLR",
                now,
                now.plusDays(730),
                BouncyCastleProvider.PROVIDER_NAME);

        KeyPairGenerateResponseDto response = new KeyPairGenerateResponseDto();
        response.setCertificate(MdocCertificateFactory.toPem(fresh));
        when(keymanagerService.getCertificate(eq("CERTIFY_DS_ACME"), eq(Optional.of(Constants.EC_SECP256R1_SIGN))))
                .thenReturn(response);

        mdocPkiService.ensureDocumentSignerCurrent(issuer);

        verify(keymanagerService, never()).generateECSignKey(anyString(), any());
        verify(keymanagerService, never()).uploadCertificate(any());
    }

    @Test
    public void ensureIacaDsTrustChain_RebuildsRootSignedPlaceholders() throws Exception {
        Issuer issuer = new Issuer();
        issuer.setIssuerId("acme");
        issuer.setMdocIacaAppId("CERTIFY_IACA_ACME");
        issuer.setMdocIacaRefId(Constants.EC_SECP256R1_SIGN);
        issuer.setMdocDsAppId("CERTIFY_DS_ACME");
        issuer.setMdocDsRefId(Constants.EC_SECP256R1_SIGN);

        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        X509Certificate rootSignedIaca = MdocCertificateFactory.buildDsCertificate(
                iacaKeyPair.getPrivate(),
                iacaKeyPair.getPublic(),
                iacaKeyPair.getPublic(),
                new org.bouncycastle.asn1.x500.X500Name("CN=www.example.com (ROOT)"),
                "www.example.com (CERTIFY_IACA_ACME-EC_SECP256R1_SIGN)",
                "MOSIP",
                "CERTIFY",
                "IN",
                "KA",
                "BLR",
                now,
                now.plusDays(30),
                BouncyCastleProvider.PROVIDER_NAME);
        X509Certificate rootSignedDs = MdocCertificateFactory.buildDsCertificate(
                iacaKeyPair.getPrivate(),
                iacaKeyPair.getPublic(),
                dsKeyPair.getPublic(),
                new org.bouncycastle.asn1.x500.X500Name("CN=www.example.com (ROOT)"),
                "www.example.com (CERTIFY_DS_ACME-EC_SECP256R1_SIGN)",
                "MOSIP",
                "CERTIFY",
                "IN",
                "KA",
                "BLR",
                now,
                now.plusDays(30),
                BouncyCastleProvider.PROVIDER_NAME);

        KeyPairGenerateResponseDto iacaResponse = new KeyPairGenerateResponseDto();
        iacaResponse.setCertificate(MdocCertificateFactory.toPem(rootSignedIaca));
        KeyPairGenerateResponseDto dsResponse = new KeyPairGenerateResponseDto();
        dsResponse.setCertificate(MdocCertificateFactory.toPem(rootSignedDs));
        when(keymanagerService.getCertificate(eq("CERTIFY_IACA_ACME"), eq(Optional.of(Constants.EC_SECP256R1_SIGN))))
                .thenReturn(iacaResponse);
        when(keymanagerService.getCertificate(eq("CERTIFY_DS_ACME"), eq(Optional.of(Constants.EC_SECP256R1_SIGN))))
                .thenReturn(dsResponse);

        stubSignatureMaterial("CERTIFY_IACA_ACME", iacaKeyPair);
        stubSignatureMaterial("CERTIFY_DS_ACME", dsKeyPair);

        org.mockito.Mockito.doAnswer(invocation -> {
            UploadCertificateRequestDto req = invocation.getArgument(0);
            KeyPairGenerateResponseDto updated = new KeyPairGenerateResponseDto();
            updated.setCertificate(req.getCertificateData());
            when(keymanagerService.getCertificate(eq(req.getApplicationId()),
                    eq(Optional.of(req.getReferenceId())))).thenReturn(updated);
            return null;
        }).when(keymanagerService).uploadCertificate(any(UploadCertificateRequestDto.class));

        mdocPkiService.ensureIacaDsTrustChain(issuer);

        ArgumentCaptor<UploadCertificateRequestDto> uploadCaptor =
                ArgumentCaptor.forClass(UploadCertificateRequestDto.class);
        verify(keymanagerService, times(2)).uploadCertificate(uploadCaptor.capture());

        X509Certificate uploadedIaca = parsePem(uploadCaptor.getAllValues().get(0).getCertificateData());
        X509Certificate uploadedDs = parsePem(uploadCaptor.getAllValues().get(1).getCertificateData());
        assertEquals(uploadedIaca.getSubjectX500Principal(), uploadedIaca.getIssuerX500Principal());
        assertEquals(uploadedIaca.getSubjectX500Principal(), uploadedDs.getIssuerX500Principal());
        uploadedDs.verify(iacaKeyPair.getPublic());
    }

    @Test
    public void getDocumentSignerKeyMaterial_WhenKeyManagerKeepsRootSigned_EmbedsInMemoryDs() throws Exception {
        Issuer issuer = new Issuer();
        issuer.setIssuerId("acme");
        issuer.setMdocIacaAppId("CERTIFY_IACA_ACME");
        issuer.setMdocIacaRefId(Constants.EC_SECP256R1_SIGN);
        issuer.setMdocDsAppId("CERTIFY_DS_ACME");
        issuer.setMdocDsRefId(Constants.EC_SECP256R1_SIGN);

        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        X509Certificate rootSignedIaca = MdocCertificateFactory.buildDsCertificate(
                iacaKeyPair.getPrivate(),
                iacaKeyPair.getPublic(),
                iacaKeyPair.getPublic(),
                new org.bouncycastle.asn1.x500.X500Name("CN=www.example.com (ROOT)"),
                "www.example.com (CERTIFY_IACA_ACME-EC_SECP256R1_SIGN)",
                "MOSIP",
                "CERTIFY",
                "IN",
                "KA",
                "BLR",
                now,
                now.plusDays(7300),
                BouncyCastleProvider.PROVIDER_NAME);
        X509Certificate rootSignedDs = MdocCertificateFactory.buildDsCertificate(
                iacaKeyPair.getPrivate(),
                iacaKeyPair.getPublic(),
                dsKeyPair.getPublic(),
                new org.bouncycastle.asn1.x500.X500Name("CN=www.example.com (ROOT)"),
                "www.example.com (CERTIFY_DS_ACME-EC_SECP256R1_SIGN)",
                "MOSIP",
                "CERTIFY",
                "IN",
                "KA",
                "BLR",
                now,
                now.plusDays(730),
                BouncyCastleProvider.PROVIDER_NAME);

        // Persistently return ROOT-signed placeholders even after uploadCertificate.
        KeyPairGenerateResponseDto iacaResponse = new KeyPairGenerateResponseDto();
        iacaResponse.setCertificate(MdocCertificateFactory.toPem(rootSignedIaca));
        KeyPairGenerateResponseDto dsResponse = new KeyPairGenerateResponseDto();
        dsResponse.setCertificate(MdocCertificateFactory.toPem(rootSignedDs));
        when(keymanagerService.getCertificate(eq("CERTIFY_IACA_ACME"), eq(Optional.of(Constants.EC_SECP256R1_SIGN))))
                .thenReturn(iacaResponse);
        when(keymanagerService.getCertificate(eq("CERTIFY_DS_ACME"), eq(Optional.of(Constants.EC_SECP256R1_SIGN))))
                .thenReturn(dsResponse);

        stubSignatureMaterial("CERTIFY_IACA_ACME", iacaKeyPair);
        stubSignatureMaterial("CERTIFY_DS_ACME", dsKeyPair);

        MdocDsKeyMaterial keyMaterial = mdocPkiService.getDocumentSignerKeyMaterial(issuer);

        assertEquals(dsKeyPair.getPrivate(), keyMaterial.privateKey());
        assertTrue(keyMaterial.certificate().getIssuerX500Principal().getName().contains("IACA-acme"));
        assertFalse(keyMaterial.certificate().getIssuerX500Principal().getName().contains("ROOT"));
        keyMaterial.certificate().verify(iacaKeyPair.getPublic());
    }

    @Test
    public void exportIacaCertificatePem_ReturnsPem() throws Exception {
        Issuer issuer = new Issuer();
        issuer.setIssuerId("acme");
        issuer.setMdocIacaAppId("CERTIFY_IACA_ACME");
        issuer.setMdocIacaRefId(Constants.EC_SECP256R1_SIGN);

        X509Certificate iaca = buildTempIaca();
        KeyPairGenerateResponseDto response = new KeyPairGenerateResponseDto();
        response.setCertificate(MdocCertificateFactory.toPem(iaca));
        when(keymanagerService.getCertificate(eq("CERTIFY_IACA_ACME"), eq(Optional.of(Constants.EC_SECP256R1_SIGN))))
                .thenReturn(response);

        String pem = mdocPkiService.exportIacaCertificatePem(issuer);
        assertTrue(pem.contains("BEGIN CERTIFICATE"));
        assertEquals(iaca, parsePem(pem));
    }

    @Test
    public void exportIacaCertificatePem_MissingRefs_Throws() {
        Issuer issuer = new Issuer();
        issuer.setIssuerId("acme");
        try {
            mdocPkiService.exportIacaCertificatePem(issuer);
            fail("expected CertifyException");
        } catch (CertifyException e) {
            assertEquals(ErrorConstants.MDOC_IACA_NOT_CONFIGURED, e.getErrorCode());
        }
    }

    private X509Certificate buildTempIaca() throws Exception {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        return MdocCertificateFactory.buildIacaCertificate(
                iacaKeyPair.getPrivate(),
                iacaKeyPair.getPublic(),
                "IACA-acme",
                "MOSIP",
                "CERTIFY",
                "IN",
                "KA",
                "BLR",
                now,
                now.plusDays(7300),
                BouncyCastleProvider.PROVIDER_NAME);
    }

    private void stubSignatureMaterial(String appId, KeyPair keyPair) throws Exception {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        X509Certificate placeholder = MdocCertificateFactory.buildIacaCertificate(
                keyPair.getPrivate(),
                keyPair.getPublic(),
                "placeholder-" + appId,
                "MOSIP",
                "CERTIFY",
                "IN",
                "KA",
                "BLR",
                now,
                now.plusDays(30),
                BouncyCastleProvider.PROVIDER_NAME);
        CertificateEntry<X509Certificate, java.security.PrivateKey> entry =
                new CertificateEntry<>(new X509Certificate[]{placeholder}, keyPair.getPrivate());
        SignatureCertificate signatureCertificate = new SignatureCertificate(
                "alias", entry, now, now.plusDays(30), BouncyCastleProvider.PROVIDER_NAME, "uid");
        when(keymanagerService.getSignatureCertificate(eq(appId), eq(Optional.of(Constants.EC_SECP256R1_SIGN)), anyString()))
                .thenReturn(signatureCertificate);
    }

    private static X509Certificate parsePem(String pem) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(
                new java.io.ByteArrayInputStream(pem.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }
}
