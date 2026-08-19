/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.mdoc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Builds IACA (CA) and Document Signer (end-entity) X.509 certificates for mdoc PKI
 * aligned with ISO/IEC 18013-5 certificate profiles used by Multipaz readers.
 */
final class MdocCertificateFactory {

    private static final String SIGN_ALGORITHM = "SHA256withECDSA";
    /**
     * ISO/IEC 18013-5 document signer EKU OID.
     */
    static final String MDOC_DOCUMENT_SIGNER_EKU_OID = "1.0.18013.5.1.2";
    private static final KeyPurposeId MDOC_DOCUMENT_SIGNER_EKU =
            KeyPurposeId.getInstance(new ASN1ObjectIdentifier(MDOC_DOCUMENT_SIGNER_EKU_OID));

    private MdocCertificateFactory() {
    }

    /**
     * Optional ISO profile extras (IAN / CRL DP). Blank values are omitted.
     */
    record ProfileOptions(String issuerAltNameEmail, String issuerAltNameUri, String crlDistributionPointUri) {
        static ProfileOptions empty() {
            return new ProfileOptions(null, null, null);
        }
    }

    static X509Certificate buildIacaCertificate(
            PrivateKey iacaPrivateKey,
            PublicKey iacaPublicKey,
            String commonName,
            String organization,
            String organizationalUnit,
            String country,
            String state,
            String location,
            LocalDateTime notBefore,
            LocalDateTime notAfter,
            String providerName) throws Exception {
        return buildIacaCertificate(iacaPrivateKey, iacaPublicKey, commonName, organization, organizationalUnit,
                country, state, location, notBefore, notAfter, providerName, ProfileOptions.empty());
    }

    static X509Certificate buildIacaCertificate(
            PrivateKey iacaPrivateKey,
            PublicKey iacaPublicKey,
            String commonName,
            String organization,
            String organizationalUnit,
            String country,
            String state,
            String location,
            LocalDateTime notBefore,
            LocalDateTime notAfter,
            String providerName,
            ProfileOptions profileOptions) throws Exception {
        X500Name subject = buildDn(commonName, organization, organizationalUnit, country, state, location);
        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        // pathLenConstraint=0: IACA may issue only end-entity (DS) certificates.
        return buildCertificate(
                iacaPrivateKey,
                iacaPublicKey,
                iacaPublicKey,
                subject,
                subject,
                keyUsage,
                new BasicConstraints(0),
                null,
                notBefore,
                notAfter,
                providerName,
                profileOptions);
    }

    static X509Certificate buildDsCertificate(
            PrivateKey iacaPrivateKey,
            PublicKey iacaPublicKey,
            PublicKey dsPublicKey,
            X500Name iacaSubject,
            String commonName,
            String organization,
            String organizationalUnit,
            String country,
            String state,
            String location,
            LocalDateTime notBefore,
            LocalDateTime notAfter,
            String providerName) throws Exception {
        return buildDsCertificate(iacaPrivateKey, iacaPublicKey, dsPublicKey, iacaSubject, commonName, organization,
                organizationalUnit, country, state, location, notBefore, notAfter, providerName, ProfileOptions.empty());
    }

    static X509Certificate buildDsCertificate(
            PrivateKey iacaPrivateKey,
            PublicKey iacaPublicKey,
            PublicKey dsPublicKey,
            X500Name iacaSubject,
            String commonName,
            String organization,
            String organizationalUnit,
            String country,
            String state,
            String location,
            LocalDateTime notBefore,
            LocalDateTime notAfter,
            String providerName,
            ProfileOptions profileOptions) throws Exception {
        X500Name subject = buildDn(commonName, organization, organizationalUnit, country, state, location);
        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature);
        return buildCertificate(
                iacaPrivateKey,
                dsPublicKey,
                iacaPublicKey,
                iacaSubject,
                subject,
                keyUsage,
                new BasicConstraints(false),
                new ExtendedKeyUsage(MDOC_DOCUMENT_SIGNER_EKU),
                notBefore,
                notAfter,
                providerName,
                profileOptions);
    }

    static String toPem(X509Certificate certificate) throws Exception {
        String encoded = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----";
    }

    static X500Name toX500Name(X509Certificate certificate) {
        return new X500Name(RFC4519Style.INSTANCE, certificate.getSubjectX500Principal().getName());
    }

    /**
     * True when IACA matches the Multipaz/ISO profile used for trust anchoring.
     */
    static boolean hasIsoIacaProfile(X509Certificate iacaCert) {
        if (iacaCert == null || iacaCert.getBasicConstraints() != 0) {
            return false;
        }
        boolean[] ku = iacaCert.getKeyUsage();
        if (ku == null || !ku[5] || !ku[6]) { // keyCertSign, cRLSign
            return false;
        }
        return iacaCert.getExtensionValue(Extension.subjectKeyIdentifier.getId()) != null
                && iacaCert.getExtensionValue(Extension.authorityKeyIdentifier.getId()) != null;
    }

    /**
     * True when DS matches the Multipaz/ISO document-signer profile.
     */
    static boolean hasIsoDsProfile(X509Certificate dsCert) {
        if (dsCert == null || dsCert.getBasicConstraints() != -1) {
            return false;
        }
        try {
            List<String> eku = dsCert.getExtendedKeyUsage();
            if (eku == null || !eku.contains(MDOC_DOCUMENT_SIGNER_EKU_OID)) {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
        Set<String> critical = dsCert.getCriticalExtensionOIDs();
        if (critical == null || !critical.contains(Extension.extendedKeyUsage.getId())) {
            return false;
        }
        return dsCert.getExtensionValue(Extension.authorityKeyIdentifier.getId()) != null
                && dsCert.getExtensionValue(Extension.subjectKeyIdentifier.getId()) != null;
    }

    private static X509Certificate buildCertificate(
            PrivateKey signPrivateKey,
            PublicKey publicKey,
            PublicKey issuerPublicKey,
            X500Name issuer,
            X500Name subject,
            KeyUsage keyUsage,
            BasicConstraints basicConstraints,
            ExtendedKeyUsage extendedKeyUsage,
            LocalDateTime notBefore,
            LocalDateTime notAfter,
            String providerName,
            ProfileOptions profileOptions) throws Exception {
        BigInteger serial = new BigInteger(64, new SecureRandom()).abs();
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(SIGN_ALGORITHM);
        if (providerName != null && !providerName.isBlank()) {
            signerBuilder.setProvider(providerName);
        }
        ContentSigner contentSigner = signerBuilder.build(signPrivateKey);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                toDate(notBefore),
                toDate(notAfter),
                subject,
                publicKey);
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(publicKey));
        AuthorityKeyIdentifier authorityKeyIdentifier = extUtils.createAuthorityKeyIdentifier(issuerPublicKey);
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
        certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
        if (extendedKeyUsage != null) {
            // ISO/Multipaz expect document-signer EKU to be critical.
            certBuilder.addExtension(Extension.extendedKeyUsage, true, extendedKeyUsage);
        }
        addOptionalIssuerAlternativeName(certBuilder, profileOptions);
        addOptionalCrlDistributionPoint(certBuilder, profileOptions);
        X509CertificateHolder holder = certBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private static void addOptionalIssuerAlternativeName(
            X509v3CertificateBuilder certBuilder, ProfileOptions profileOptions) throws Exception {
        if (profileOptions == null) {
            return;
        }
        List<GeneralName> names = new ArrayList<>();
        if (profileOptions.issuerAltNameEmail() != null && !profileOptions.issuerAltNameEmail().isBlank()) {
            names.add(new GeneralName(GeneralName.rfc822Name, profileOptions.issuerAltNameEmail().trim()));
        }
        if (profileOptions.issuerAltNameUri() != null && !profileOptions.issuerAltNameUri().isBlank()) {
            names.add(new GeneralName(GeneralName.uniformResourceIdentifier, profileOptions.issuerAltNameUri().trim()));
        }
        if (!names.isEmpty()) {
            certBuilder.addExtension(Extension.issuerAlternativeName, false,
                    new GeneralNames(names.toArray(GeneralName[]::new)));
        }
    }

    private static void addOptionalCrlDistributionPoint(
            X509v3CertificateBuilder certBuilder, ProfileOptions profileOptions) throws Exception {
        if (profileOptions == null
                || profileOptions.crlDistributionPointUri() == null
                || profileOptions.crlDistributionPointUri().isBlank()) {
            return;
        }
        GeneralName crlLocation = new GeneralName(
                GeneralName.uniformResourceIdentifier, profileOptions.crlDistributionPointUri().trim());
        DistributionPointName distributionPointName = new DistributionPointName(new GeneralNames(crlLocation));
        CRLDistPoint crlDistPoint = new CRLDistPoint(new DistributionPoint[]{
                new DistributionPoint(distributionPointName, null, null)
        });
        certBuilder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);
    }

    private static X500Name buildDn(
            String commonName,
            String organization,
            String organizationalUnit,
            String country,
            String state,
            String location) {
        X500NameBuilder builder = new X500NameBuilder(RFC4519Style.INSTANCE);
        addRdn(builder, BCStyle.C, country);
        addRdn(builder, BCStyle.ST, state);
        addRdn(builder, BCStyle.L, location);
        addRdn(builder, BCStyle.O, organization);
        addRdn(builder, BCStyle.OU, organizationalUnit);
        addRdn(builder, BCStyle.CN, commonName);
        return builder.build();
    }

    private static void addRdn(X500NameBuilder builder, ASN1ObjectIdentifier oid, String value) {
        if (value != null && !value.isBlank()) {
            builder.addRDN(oid, value);
        }
    }

    private static Date toDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.toInstant(ZoneOffset.UTC));
    }
}
