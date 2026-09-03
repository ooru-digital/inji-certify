/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.Issuer;
import io.mosip.certify.utils.DIDDocumentUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DidDocumentServiceTest {

    @Mock
    private IssuerResolver issuerResolver;

    @Mock
    private DIDDocumentUtil didDocumentUtil;

    @InjectMocks
    private DidDocumentService didDocumentService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getDIDDocument_usesResolvedIssuer() {
        Issuer issuer = new Issuer();
        issuer.setIssuerId("DEFAU-RPHHS");
        issuer.setDidUrl("did:web:example.com:issuers:DEFAU-RPHHS");
        Map<String, Object> didDocument = Map.of("id", issuer.getDidUrl());

        when(issuerResolver.resolve("DEFAU-RPHHS")).thenReturn(issuer);
        when(didDocumentUtil.generateDIDDocument(issuer)).thenReturn(didDocument);

        Map<String, Object> result = didDocumentService.getDIDDocument("DEFAU-RPHHS");

        assertEquals(issuer.getDidUrl(), result.get("id"));
        verify(issuerResolver).resolve("DEFAU-RPHHS");
        verify(didDocumentUtil).generateDIDDocument(issuer);
    }

    @Test
    void getDIDDocument_nullIssuerId_resolvesDefault() {
        Issuer issuer = new Issuer();
        issuer.setIssuerId("default");
        Map<String, Object> didDocument = Map.of("id", "did:web:example.com");

        when(issuerResolver.resolve(null)).thenReturn(issuer);
        when(didDocumentUtil.generateDIDDocument(issuer)).thenReturn(didDocument);

        assertEquals("did:web:example.com", didDocumentService.getDIDDocument(null).get("id"));
        verify(issuerResolver).resolve(null);
    }

    @Test
    void getDIDDocument_unknownIssuer_propagates() {
        when(issuerResolver.resolve("missing")).thenThrow(
                new CertifyException(ErrorConstants.ISSUER_NOT_FOUND, "Issuer not found: missing"));

        CertifyException ex = assertThrows(CertifyException.class,
                () -> didDocumentService.getDIDDocument("missing"));
        assertEquals(ErrorConstants.ISSUER_NOT_FOUND, ex.getErrorCode());
    }
}
