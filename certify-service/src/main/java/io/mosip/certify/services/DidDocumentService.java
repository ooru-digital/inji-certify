/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.entity.Issuer;
import io.mosip.certify.utils.DIDDocumentUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Serves DID documents from onboarded issuer keys. Independent of
 * {@code mosip.certify.plugin-mode} — DID hosting is not an issuance-plugin concern.
 */
@Slf4j
@Service
public class DidDocumentService {

    @Autowired
    private IssuerResolver issuerResolver;

    @Autowired
    private DIDDocumentUtil didDocumentUtil;

    public Map<String, Object> getDIDDocument(String issuerId) {
        Issuer issuer = issuerResolver.resolve(issuerId);
        log.debug("Generating DID document for issuer {}", issuer.getIssuerId());
        return didDocumentUtil.generateDIDDocument(issuer);
    }
}
