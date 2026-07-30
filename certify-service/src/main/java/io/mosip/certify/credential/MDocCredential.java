/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.credential;

import java.util.*;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.mdoc.MdocDsKeyMaterial;
import io.mosip.certify.mdoc.MdocLocalDsCoseSigner;
import io.mosip.certify.utils.MDocProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.service.SignatureService;
import lombok.extern.slf4j.Slf4j;

/**
 * MDocCredential implementation for ISO 18013-5 compliant mobile documents
 * Handles mDoc structure creation, namespace processing, and COSE signing
 */
@Slf4j
@Component
public class MDocCredential extends Credential {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private MDocProcessor mDocProcessor;

    @Autowired(required = false)
    private MdocLocalDsCoseSigner mdocLocalDsCoseSigner;

    public MDocCredential(VCFormatter vcFormatter, SignatureService signatureService) {
        super(vcFormatter, signatureService);
    }

    @Override
    public boolean canHandle(String format) {
        return VCFormats.MSO_MDOC.equals(format);
    }

    @Override
    public String createCredential(Map<String, Object> updatedTemplateParams, String templateName) {
        try {
            String templatedJSON = super.createCredential(updatedTemplateParams, templateName);
            Map<String, Object> finalMDoc = mDocProcessor.processTemplatedJson(templatedJSON, updatedTemplateParams);
            return objectMapper.writeValueAsString(finalMDoc);

        } catch (Exception e) {
            log.error("Error creating mDoc credential: {}", e.getMessage(), e);
            throw new CertifyException("MDOC_CREATION_FAILED", "Failed to create mDoc credential", e);
        }
    }

    @Override
    public VCResult<?> addProof(String vcToSign, String headers, String signAlgorithm, String appID, String refID, String didUrl, String signatureCryptoSuite) {
        try {
            return buildSignedCredential(vcToSign, mso -> mDocProcessor.signMSO(mso, appID, refID, signAlgorithm));
        } catch (Exception e) {
            log.error("Error adding proof to mDoc: {}", e.getMessage(), e);
            throw new CertifyException("MDOC_PROOF_FAILED", "Failed to add proof to mDoc", e);
        }
    }

    /**
     * Signs with an explicit Document Signer key/cert (IACA-issued), used by OID4VCI after
     * {@code MdocPkiService.getDocumentSignerKeyMaterial}.
     */
    public VCResult<?> addProofWithLocalDs(String vcToSign, MdocDsKeyMaterial keyMaterial) {
        if (mdocLocalDsCoseSigner == null) {
            throw new CertifyException("MDOC_PROOF_FAILED",
                    "Local Document Signer COSE signer is not available");
        }
        try {
            return buildSignedCredential(vcToSign,
                    mso -> mDocProcessor.signMSOWithLocalDs(mso, keyMaterial, mdocLocalDsCoseSigner));
        } catch (Exception e) {
            log.error("Error adding proof to mDoc with local DS: {}", e.getMessage(), e);
            throw new CertifyException("MDOC_PROOF_FAILED", "Failed to add proof to mDoc", e);
        }
    }

    @FunctionalInterface
    private interface MsoSigner {
        byte[] sign(Map<String, Object> mso) throws Exception;
    }

    private VCResult<?> buildSignedCredential(String vcToSign, MsoSigner signer) throws Exception {
        VCResult<String> vcResult = new VCResult<>();

        @SuppressWarnings("unchecked")
        Map<String, Object> mDocJson = objectMapper.readValue(vcToSign, Map.class);
        Map<String, Object> saltedNamespaces = MDocProcessor.addRandomSalts(mDocJson);
        Map<String, Map<Integer, byte[]>> namespaceDigests = new HashMap<>();
        Map<String, Object> taggedNamespaces = MDocProcessor.calculateDigests(saltedNamespaces, namespaceDigests);

        Map<String, Object> mso = mDocProcessor.createMobileSecurityObject(mDocJson, namespaceDigests);
        byte[] signedMSO = signer.sign(mso);
        Map<String, Object> issuerSigned = MDocProcessor.createIssuerSignedStructure(taggedNamespaces, signedMSO);
        Map<String, Object> mDocSignedCredential = new HashMap<>();
        mDocSignedCredential.put(Constants.DOCTYPE, mso.get(Constants.DOCTYPE));
        mDocSignedCredential.put("issuerSigned", issuerSigned);
        byte[] cborIssuerSigned = MDocProcessor.encodeToCBOR(mDocSignedCredential);
        String base64UrlCredential = Base64.getUrlEncoder().withoutPadding().encodeToString(cborIssuerSigned);

        vcResult.setCredential(base64UrlCredential);
        vcResult.setFormat(VCFormats.MSO_MDOC);
        return vcResult;
    }
}