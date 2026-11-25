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
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Provisions and rotates mdoc IACA / Document Signer material via MOSIP KeyManager.
 */
@Slf4j
@Service
public class MdocPkiService {

    private static final String CREATED_BY = "certify-mdoc-pki";

    /**
     * SoftHSM/PKCS12 often ignores {@code uploadCertificate} and keeps ROOT-signed placeholders.
     * Cache rebuilt self-signed IACA so export and signing share the same trust-anchor bytes.
     */
    private final ConcurrentHashMap<String, X509Certificate> rebuiltIacaByKey = new ConcurrentHashMap<>();

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private KeyPolicyRepository keyPolicyRepository;

    @Value("${mosip.certify.mdoc.iaca.key-policy.validity-days:7300}")
    private int iacaValidityDays;

    @Value("${mosip.certify.mdoc.iaca.key-policy.pre-expire-days:90}")
    private int iacaPreExpireDays;

    @Value("${mosip.certify.mdoc.ds.key-policy.validity-days:457}")
    private int dsValidityDays;

    @Value("${mosip.certify.mdoc.ds.key-policy.pre-expire-days:60}")
    private int dsPreExpireDays;

    @Value("${mosip.certify.mdoc.iaca.certificate.common-name-prefix:IACA-}")
    private String iacaCnPrefix;

    @Value("${mosip.certify.mdoc.ds.certificate.common-name-prefix:DS-}")
    private String dsCnPrefix;

    @Value("${mosip.certify.mdoc.certificate.organization:${mosip.kernel.keymanager.certificate.default.organization:MOSIP}}")
    private String organization;

    @Value("${mosip.certify.mdoc.certificate.organizational-unit:${mosip.kernel.keymanager.certificate.default.organizational-unit:CERTIFY}}")
    private String organizationalUnit;

    @Value("${mosip.certify.mdoc.certificate.country:${mosip.kernel.keymanager.certificate.default.country:IN}}")
    private String country;

    @Value("${mosip.certify.mdoc.certificate.state:${mosip.kernel.keymanager.certificate.default.state:}}")
    private String state;

    @Value("${mosip.certify.mdoc.certificate.location:${mosip.kernel.keymanager.certificate.default.location:}}")
    private String location;

    @Value("${mosip.certify.mdoc.certificate.issuer-alternative-name.email:}")
    private String issuerAlternativeNameEmail;

    @Value("${mosip.certify.mdoc.certificate.issuer-alternative-name.uri:}")
    private String issuerAlternativeNameUri;

    @Value("${mosip.certify.mdoc.certificate.crl-distribution-point-uri:}")
    private String crlDistributionPointUri;

    /**
     * Creates IACA + DS EC P-256 keys, rebuilds IACA→DS certificate chain, uploads to KeyManager.
     */
    public MdocPkiRefs provision(String issuerId) {
        String iacaAppId = buildAppId(IssuerConstants.IACA_APP_ID_PREFIX, issuerId);
        String dsAppId = buildAppId(IssuerConstants.DS_APP_ID_PREFIX, issuerId);
        String refId = Constants.EC_SECP256R1_SIGN;

        try {
            ensureKeyPolicy(iacaAppId, iacaValidityDays, iacaPreExpireDays);
            ensureKeyPolicy(dsAppId, dsValidityDays, dsPreExpireDays);

            generateEcSignKey(iacaAppId, refId, false);
            generateEcSignKey(dsAppId, refId, false);

            X509Certificate iacaCert = rebuildAndUploadIaca(iacaAppId, refId, issuerId);
            rebuildAndUploadDs(iacaAppId, dsAppId, refId, issuerId, iacaCert);

            log.info("Provisioned mdoc IACA/DS keys for issuer {} (iaca={}, ds={})", issuerId, iacaAppId, dsAppId);
            return new MdocPkiRefs(iacaAppId, refId, dsAppId, refId);
        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to provision mdoc IACA/DS for issuer {}", issuerId, e);
            throw new CertifyException(ErrorConstants.MDOC_PKI_PROVISIONING_FAILED,
                    "Failed to provision mdoc IACA/DS keys for issuer: " + issuerId);
        }
    }

    /**
     * Force-rotates Document Signer keypair and re-signs DS certificate with existing IACA.
     */
    public void rotateDocumentSigner(Issuer issuer) {
        if (issuer == null
                || StringUtils.isBlank(issuer.getMdocIacaAppId())
                || StringUtils.isBlank(issuer.getMdocDsAppId())) {
            throw new CertifyException(ErrorConstants.MDOC_DS_ROTATION_FAILED,
                    "Issuer is missing mdoc IACA/DS KeyManager references");
        }
        String iacaAppId = issuer.getMdocIacaAppId();
        String dsAppId = issuer.getMdocDsAppId();
        String iacaRefId = StringUtils.defaultIfBlank(issuer.getMdocIacaRefId(), Constants.EC_SECP256R1_SIGN);
        String dsRefId = StringUtils.defaultIfBlank(issuer.getMdocDsRefId(), Constants.EC_SECP256R1_SIGN);

        try {
            generateEcSignKey(dsAppId, dsRefId, true);
            SignatureCertificate iacaMaterial = loadSignatureCertificate(iacaAppId, iacaRefId);
            X509Certificate iacaCert = iacaMaterial.getCertificateEntry().getChain()[0];
            rebuildAndUploadDs(iacaAppId, dsAppId, iacaRefId, dsRefId, issuer.getIssuerId(), iacaCert);
            log.info("Rotated mdoc Document Signer for issuer {}", issuer.getIssuerId());
        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to rotate mdoc DS for issuer {}", issuer.getIssuerId(), e);
            throw new CertifyException(ErrorConstants.MDOC_DS_ROTATION_FAILED,
                    "Failed to rotate mdoc Document Signer for issuer: " + issuer.getIssuerId());
        }
    }

    /**
     * Returns true when the current DS certificate is missing, expired, or within pre-expire window.
     */
    public boolean isDsRotationDue(Issuer issuer) {
        if (issuer == null || StringUtils.isBlank(issuer.getMdocDsAppId())) {
            return false;
        }
        String refId = StringUtils.defaultIfBlank(issuer.getMdocDsRefId(), Constants.EC_SECP256R1_SIGN);
        try {
            X509Certificate dsCert = loadCertificate(issuer.getMdocDsAppId(), refId);
            LocalDateTime notAfter = LocalDateTime.ofInstant(dsCert.getNotAfter().toInstant(), ZoneOffset.UTC);
            LocalDateTime rotateAfter = notAfter.minusDays(dsPreExpireDays);
            return !LocalDateTime.now(ZoneOffset.UTC).isBefore(rotateAfter);
        } catch (Exception e) {
            log.warn("Unable to read DS certificate for issuer {}; treating as rotation due: {}",
                    issuer.getIssuerId(), e.getMessage());
            return true;
        }
    }

    /**
     * Ensures ISO mdoc trust material is ready before signing:
     * <ol>
     *   <li>IACA is self-signed (not the KeyManager default ROOT-signed placeholder)</li>
     *   <li>DS is issued by that IACA</li>
     *   <li>DS is within its validity window (otherwise force-rotate)</li>
     * </ol>
     */
    public void ensureDocumentSignerCurrent(Issuer issuer) {
        ensureIacaDsTrustChain(issuer);
        if (!isDsRotationDue(issuer)) {
            return;
        }
        log.info("Document Signer near expiry/expired for issuer {}; rotating on demand",
                issuer != null ? issuer.getIssuerId() : "null");
        rotateDocumentSigner(issuer);
        // Rotation replaces the DS key; re-assert IACA→DS linkage after upload.
        ensureIacaDsTrustChain(issuer);
    }

    /**
     * Repairs KeyManager-stored mdoc certificates when they are still the default
     * ROOT-signed placeholders created by {@code generateECSignKey}.
     * <p>
     * Multipaz / ISO 18013-5 readers trust the IACA subject, so DS.issuer must equal IACA.subject.
     */
    public void ensureIacaDsTrustChain(Issuer issuer) {
        if (issuer == null
                || StringUtils.isBlank(issuer.getMdocIacaAppId())
                || StringUtils.isBlank(issuer.getMdocDsAppId())) {
            return;
        }
        String iacaAppId = issuer.getMdocIacaAppId();
        String dsAppId = issuer.getMdocDsAppId();
        String iacaRefId = StringUtils.defaultIfBlank(issuer.getMdocIacaRefId(), Constants.EC_SECP256R1_SIGN);
        String dsRefId = StringUtils.defaultIfBlank(issuer.getMdocDsRefId(), Constants.EC_SECP256R1_SIGN);
        String issuerId = issuer.getIssuerId();

        try {
            X509Certificate iacaCert = loadCertificate(iacaAppId, iacaRefId);
            if (!isSelfSigned(iacaCert) || !MdocCertificateFactory.hasIsoIacaProfile(iacaCert)) {
                log.warn("IACA cert for issuer {} needs rebuild (selfSigned={}, isoProfile={})",
                        issuerId, isSelfSigned(iacaCert), MdocCertificateFactory.hasIsoIacaProfile(iacaCert));
                rebuiltIacaByKey.remove(iacaAppId + "#" + iacaRefId);
                X509Certificate rebuiltIaca = rebuildAndUploadIaca(iacaAppId, iacaRefId, issuerId);
                try {
                    iacaCert = assertPersistedMatches(iacaAppId, iacaRefId, rebuiltIaca);
                } catch (CertifyException persistEx) {
                    log.error("IACA rebuild uploaded but KeyManager still returns a different cert; "
                            + "continuing with in-memory self-signed IACA for issuer {}: {}",
                            issuerId, persistEx.getMessage());
                    iacaCert = rebuiltIaca;
                }
            }

            X509Certificate dsCert = loadCertificate(dsAppId, dsRefId);
            if (!isIssuedBy(dsCert, iacaCert)
                    || !verifiesWithIssuer(dsCert, iacaCert)
                    || !MdocCertificateFactory.hasIsoDsProfile(dsCert)
                    || !authorityKeyMatchesIssuerSki(dsCert, iacaCert)) {
                log.warn("DS cert for issuer {} needs rebuild (issuedByIaca={}, isoProfile={})",
                        issuerId,
                        isIssuedBy(dsCert, iacaCert) && verifiesWithIssuer(dsCert, iacaCert),
                        MdocCertificateFactory.hasIsoDsProfile(dsCert));
                X509Certificate rebuiltDs = rebuildAndUploadDs(iacaAppId, dsAppId, iacaRefId, dsRefId, issuerId, iacaCert);
                try {
                    assertPersistedMatches(dsAppId, dsRefId, rebuiltDs);
                } catch (CertifyException persistEx) {
                    log.error("DS rebuild uploaded but KeyManager still returns a different cert; "
                            + "signing will embed in-memory IACA-issued DS for issuer {}: {}",
                            issuerId, persistEx.getMessage());
                }
            }
        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to ensure IACA→DS trust chain for issuer {}", issuerId, e);
            throw new CertifyException(ErrorConstants.MDOC_PKI_PROVISIONING_FAILED,
                    "Failed to ensure mdoc IACA→DS trust chain for issuer: " + issuerId);
        }
    }

    /**
     * Returns Document Signer private key + an IACA-issued DS certificate for COSE x5chain.
     * Repairs KeyManager trust material first. If SoftHSM/DB still returns a ROOT-signed DS
     * after upload, embeds the freshly rebuilt in-memory DS certificate so Multipaz can trust
     * the exported IACA.
     */
    public MdocDsKeyMaterial getDocumentSignerKeyMaterial(Issuer issuer) {
        if (issuer == null
                || StringUtils.isBlank(issuer.getMdocIacaAppId())
                || StringUtils.isBlank(issuer.getMdocDsAppId())) {
            throw new CertifyException(ErrorConstants.MDOC_ISSUER_DS_NOT_CONFIGURED,
                    "Issuer is missing mdoc IACA/DS KeyManager references");
        }
        ensureDocumentSignerCurrent(issuer);

        String iacaAppId = issuer.getMdocIacaAppId();
        String dsAppId = issuer.getMdocDsAppId();
        String iacaRefId = StringUtils.defaultIfBlank(issuer.getMdocIacaRefId(), Constants.EC_SECP256R1_SIGN);
        String dsRefId = StringUtils.defaultIfBlank(issuer.getMdocDsRefId(), Constants.EC_SECP256R1_SIGN);

        try {
            PrivateKey dsPrivateKey = loadSignatureCertificate(dsAppId, dsRefId).getCertificateEntry().getPrivateKey();
            X509Certificate iacaCert = loadCertificate(iacaAppId, iacaRefId);
            // SoftHSM/DB may ignore uploadCertificate and keep ROOT-signed placeholders.
            // Keep signing/export on the same in-memory rebuilt IACA so Multipaz trust matches x5chain.
            if (!isSelfSigned(iacaCert) || !MdocCertificateFactory.hasIsoIacaProfile(iacaCert)) {
                log.warn("Persisted IACA for issuer {} is incomplete after repair; "
                                + "using freshly rebuilt self-signed IACA for DS issuance",
                        issuer.getIssuerId());
                rebuiltIacaByKey.remove(iacaAppId + "#" + iacaRefId);
                iacaCert = rebuildAndUploadIaca(iacaAppId, iacaRefId, issuer.getIssuerId());
            } else {
                X509Certificate cached = rebuiltIacaByKey.get(iacaAppId + "#" + iacaRefId);
                if (cached != null && MdocCertificateFactory.hasIsoIacaProfile(cached)) {
                    iacaCert = cached;
                }
            }

            X509Certificate dsCert = loadCertificate(dsAppId, dsRefId);
            if (isIssuedBy(dsCert, iacaCert)
                    && verifiesWithIssuer(dsCert, iacaCert)
                    && MdocCertificateFactory.hasIsoDsProfile(dsCert)
                    && authorityKeyMatchesIssuerSki(dsCert, iacaCert)) {
                return new MdocDsKeyMaterial(dsPrivateKey, dsCert);
            }

            log.warn("Persisted DS cert for issuer {} is incomplete after repair; "
                            + "embedding in-memory rebuilt DS certificate in x5chain",
                    issuer.getIssuerId());
            X509Certificate rebuiltDs = rebuildAndUploadDs(iacaAppId, dsAppId, iacaRefId, dsRefId,
                    issuer.getIssuerId(), iacaCert);
            return new MdocDsKeyMaterial(dsPrivateKey, rebuiltDs);
        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to resolve Document Signer key material for issuer {}", issuer.getIssuerId(), e);
            throw new CertifyException(ErrorConstants.MDOC_PKI_PROVISIONING_FAILED,
                    "Failed to resolve Document Signer key material for issuer: " + issuer.getIssuerId());
        }
    }

    public int getDsPreExpireDays() {
        return dsPreExpireDays;
    }

    public int getIacaValidityDays() {
        return iacaValidityDays;
    }

    public int getDsValidityDays() {
        return dsValidityDays;
    }

    /**
     * Exports the issuer IACA root certificate as PEM for verifier trust-store installation
     * (ISO/IEC 18013-5 out-of-band IACA dissemination).
     */
    public String exportIacaCertificatePem(Issuer issuer) {
        if (issuer == null
                || StringUtils.isBlank(issuer.getMdocIacaAppId())) {
            throw new CertifyException(ErrorConstants.MDOC_IACA_NOT_CONFIGURED,
                    "Issuer is missing mdoc IACA KeyManager references; cannot export trust anchor");
        }
        // Repair ROOT-signed placeholder IACA before handing it to verifiers.
        if (StringUtils.isNotBlank(issuer.getMdocDsAppId())) {
            ensureIacaDsTrustChain(issuer);
        }
        String iacaAppId = issuer.getMdocIacaAppId();
        String iacaRefId = StringUtils.defaultIfBlank(issuer.getMdocIacaRefId(), Constants.EC_SECP256R1_SIGN);
        try {
            X509Certificate iacaCert = loadCertificate(iacaAppId, iacaRefId);
            if (!isSelfSigned(iacaCert) || !MdocCertificateFactory.hasIsoIacaProfile(iacaCert)) {
                log.warn("Exporting freshly rebuilt ISO-profile IACA for issuer {} "
                                + "(selfSigned={}, isoProfile={})",
                        issuer.getIssuerId(),
                        isSelfSigned(iacaCert),
                        MdocCertificateFactory.hasIsoIacaProfile(iacaCert));
                rebuiltIacaByKey.remove(iacaAppId + "#" + iacaRefId);
                iacaCert = rebuildAndUploadIaca(iacaAppId, iacaRefId, issuer.getIssuerId());
            } else {
                X509Certificate cached = rebuiltIacaByKey.get(iacaAppId + "#" + iacaRefId);
                if (cached != null && MdocCertificateFactory.hasIsoIacaProfile(cached)) {
                    iacaCert = cached;
                }
            }
            return MdocCertificateFactory.toPem(iacaCert);
        } catch (CertifyException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to export IACA certificate for issuer {}", issuer.getIssuerId(), e);
            throw new CertifyException(ErrorConstants.MDOC_IACA_NOT_CONFIGURED,
                    "Failed to load IACA certificate for issuer: " + issuer.getIssuerId());
        }
    }

    private X509Certificate rebuildAndUploadIaca(String iacaAppId, String refId, String issuerId) throws Exception {
        String cacheKey = iacaAppId + "#" + refId;
        X509Certificate cached = rebuiltIacaByKey.get(cacheKey);
        if (cached != null && isSelfSigned(cached) && MdocCertificateFactory.hasIsoIacaProfile(cached)) {
            // Re-attempt persistence; still return the stable cached trust anchor.
            try {
                uploadCertificate(iacaAppId, refId, cached);
            } catch (Exception e) {
                log.debug("Re-upload of cached IACA for {} failed: {}", cacheKey, e.getMessage());
            }
            return cached;
        }

        SignatureCertificate iacaMaterial = loadSignatureCertificate(iacaAppId, refId);
        PrivateKey iacaPrivateKey = iacaMaterial.getCertificateEntry().getPrivateKey();
        PublicKey iacaPublicKey = iacaMaterial.getCertificateEntry().getChain()[0].getPublicKey();
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);

        X509Certificate iacaCert = MdocCertificateFactory.buildIacaCertificate(
                iacaPrivateKey,
                iacaPublicKey,
                iacaCnPrefix + issuerId,
                organization,
                organizationalUnit,
                country,
                state,
                location,
                now,
                now.plusDays(iacaValidityDays),
                iacaMaterial.getProviderName(),
                profileOptions());
        uploadCertificate(iacaAppId, refId, iacaCert);
        rebuiltIacaByKey.put(cacheKey, iacaCert);
        return iacaCert;
    }

    private X509Certificate rebuildAndUploadDs(
            String iacaAppId,
            String dsAppId,
            String refId,
            String issuerId,
            X509Certificate iacaCert) throws Exception {
        return rebuildAndUploadDs(iacaAppId, dsAppId, refId, refId, issuerId, iacaCert);
    }

    private X509Certificate rebuildAndUploadDs(
            String iacaAppId,
            String dsAppId,
            String iacaRefId,
            String dsRefId,
            String issuerId,
            X509Certificate iacaCert) throws Exception {
        SignatureCertificate iacaMaterial = loadSignatureCertificate(iacaAppId, iacaRefId);
        SignatureCertificate dsMaterial = loadSignatureCertificate(dsAppId, dsRefId);

        PrivateKey iacaPrivateKey = iacaMaterial.getCertificateEntry().getPrivateKey();
        X500Name iacaSubject = MdocCertificateFactory.toX500Name(iacaCert);
        PublicKey dsPublicKey = dsMaterial.getCertificateEntry().getChain()[0].getPublicKey();
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);

        X509Certificate dsCert = MdocCertificateFactory.buildDsCertificate(
                iacaPrivateKey,
                iacaCert.getPublicKey(),
                dsPublicKey,
                iacaSubject,
                dsCnPrefix + issuerId,
                organization,
                organizationalUnit,
                country,
                state,
                location,
                now,
                now.plusDays(dsValidityDays),
                iacaMaterial.getProviderName(),
                profileOptions());
        uploadCertificate(dsAppId, dsRefId, dsCert);
        return dsCert;
    }

    private MdocCertificateFactory.ProfileOptions profileOptions() {
        return new MdocCertificateFactory.ProfileOptions(
                issuerAlternativeNameEmail, issuerAlternativeNameUri, crlDistributionPointUri);
    }

    private static boolean authorityKeyMatchesIssuerSki(X509Certificate dsCert, X509Certificate iacaCert) {
        try {
            byte[] dsAkiExt = dsCert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
            byte[] iacaSkiExt = iacaCert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
            if (dsAkiExt == null || iacaSkiExt == null) {
                return false;
            }
            AuthorityKeyIdentifier aki =
                    AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(dsAkiExt).getOctets());
            SubjectKeyIdentifier ski =
                    SubjectKeyIdentifier.getInstance(ASN1OctetString.getInstance(iacaSkiExt).getOctets());
            return aki.getKeyIdentifier() != null
                    && java.util.Arrays.equals(aki.getKeyIdentifier(), ski.getKeyIdentifier());
        } catch (Exception e) {
            return false;
        }
    }

    private X509Certificate assertPersistedMatches(String appId, String refId, X509Certificate expected)
            throws Exception {
        X509Certificate persisted = loadCertificate(appId, refId);
        // Compare issuer/subject — public keys alone are insufficient because ROOT-signed and
        // IACA-signed DS certificates share the same keypair.
        if (!persisted.getIssuerX500Principal().equals(expected.getIssuerX500Principal())
                || !persisted.getSubjectX500Principal().equals(expected.getSubjectX500Principal())) {
            throw new CertifyException(ErrorConstants.MDOC_PKI_PROVISIONING_FAILED,
                    "KeyManager returned certificate with unexpected subject/issuer for " + appId + "/" + refId
                            + " (subject=" + persisted.getSubjectX500Principal().getName()
                            + ", issuer=" + persisted.getIssuerX500Principal().getName()
                            + "; expected subject=" + expected.getSubjectX500Principal().getName()
                            + ", expected issuer=" + expected.getIssuerX500Principal().getName() + ")");
        }
        return persisted;
    }

    private static boolean isSelfSigned(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
    }

    private static boolean isIssuedBy(X509Certificate certificate, X509Certificate issuer) {
        return certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal());
    }

    private static boolean verifiesWithIssuer(X509Certificate certificate, X509Certificate issuer) {
        try {
            certificate.verify(issuer.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private SignatureCertificate loadSignatureCertificate(String appId, String refId) {
        String timestamp = LocalDateTime.now(ZoneOffset.UTC).toString();
        SignatureCertificate certificate = keymanagerService.getSignatureCertificate(appId, Optional.of(refId), timestamp);
        CertificateEntry<X509Certificate, PrivateKey> entry = certificate.getCertificateEntry();
        if (entry == null || entry.getPrivateKey() == null || entry.getChain() == null || entry.getChain().length == 0) {
            throw new CertifyException(ErrorConstants.MDOC_PKI_PROVISIONING_FAILED,
                    "KeyManager returned incomplete signature certificate for " + appId + "/" + refId);
        }
        return certificate;
    }

    private X509Certificate loadCertificate(String appId, String refId) throws Exception {
        KeyPairGenerateResponseDto response = keymanagerService.getCertificate(appId, Optional.of(refId));
        if (response == null || StringUtils.isBlank(response.getCertificate())) {
            throw new IllegalStateException("No certificate for " + appId + "/" + refId);
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(response.getCertificate().getBytes(StandardCharsets.UTF_8)));
    }

    private void uploadCertificate(String appId, String refId, X509Certificate certificate) throws Exception {
        UploadCertificateRequestDto request = new UploadCertificateRequestDto();
        request.setApplicationId(appId);
        request.setReferenceId(refId);
        request.setCertificateData(MdocCertificateFactory.toPem(certificate));
        keymanagerService.uploadCertificate(request);
    }

    private void generateEcSignKey(String appId, String refId, boolean force) {
        KeyPairGenerateRequestDto request = new KeyPairGenerateRequestDto();
        request.setApplicationId(appId);
        request.setReferenceId(refId);
        request.setForce(force);
        keymanagerService.generateECSignKey("certificate", request);
    }

    private void ensureKeyPolicy(String appId, int validityDays, int preExpireDays) {
        if (keyPolicyRepository.findByApplicationId(appId).isPresent()) {
            return;
        }
        KeyPolicy policy = new KeyPolicy();
        policy.setApplicationId(appId);
        policy.setValidityInDays(validityDays);
        policy.setPreExpireDays(preExpireDays);
        policy.setAccessAllowed("NA");
        policy.setActive(true);
        policy.setCreatedBy(CREATED_BY);
        policy.setCreatedtimes(LocalDateTime.now());
        keyPolicyRepository.save(policy);
        log.info("Registered mdoc key policy for app id {} (validity={}d, preExpire={}d)",
                appId, validityDays, preExpireDays);
    }

    private String buildAppId(String prefix, String issuerId) {
        return KeyManagerAppIdUtil.buildAppId(prefix, issuerId);
    }
}
