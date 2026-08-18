/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class VcApiValidityResolverTest {

    private VcApiValidityResolver resolver;

    @Before
    public void setUp() {
        resolver = new VcApiValidityResolver();
        ReflectionTestUtils.setField(resolver, "defaultExpiryDuration", "P730D");
    }

    @Test
    public void resolve_usesClientDates_whenBothProvided() {
        VcApiValidityResolver.ValidityWindow window = resolver.resolve(
                "2026-07-24T06:30:00Z", "2031-07-24T06:30:00Z");

        assertEquals("2026-07-24T06:30:00.000Z", window.validFrom());
        assertEquals("2031-07-24T06:30:00.000Z", window.validUntil());
    }

    @Test
    public void resolve_acceptsMillisFormat() {
        VcApiValidityResolver.ValidityWindow window = resolver.resolve(
                "2026-07-24T06:30:00.123Z", "2031-07-24T06:30:00.456Z");

        assertEquals("2026-07-24T06:30:00.123Z", window.validFrom());
        assertEquals("2031-07-24T06:30:00.456Z", window.validUntil());
    }

    @Test
    public void resolve_fallsBackToServerDuration_whenNeitherProvided() {
        Instant before = Instant.now().minusSeconds(2);
        VcApiValidityResolver.ValidityWindow window = resolver.resolve(null, null);
        Instant after = Instant.now().plusSeconds(2);

        Instant from = Instant.parse(window.validFrom());
        Instant until = Instant.parse(window.validUntil());
        assertTrue(from.isAfter(before) || from.equals(before));
        assertTrue(from.isBefore(after) || from.equals(after));
        assertEquals(730, ChronoUnit.DAYS.between(from, until));
    }

    @Test
    public void resolve_throws_whenOnlyValidFromProvided() {
        CertifyException ex = assertThrows(CertifyException.class,
                () -> resolver.resolve("2026-07-24T06:30:00Z", null));
        assertEquals(ErrorConstants.INVALID_CREDENTIAL_VALIDITY, ex.getErrorCode());
    }

    @Test
    public void resolve_throws_whenOnlyValidUntilProvided() {
        CertifyException ex = assertThrows(CertifyException.class,
                () -> resolver.resolve(null, "2031-07-24T06:30:00Z"));
        assertEquals(ErrorConstants.INVALID_CREDENTIAL_VALIDITY, ex.getErrorCode());
    }

    @Test
    public void resolve_throws_whenValidUntilNotAfterValidFrom() {
        CertifyException ex = assertThrows(CertifyException.class,
                () -> resolver.resolve("2031-07-24T06:30:00Z", "2026-07-24T06:30:00Z"));
        assertEquals(ErrorConstants.INVALID_EXPIRY_RANGE, ex.getErrorCode());
    }

    @Test
    public void resolve_throws_whenDateUnparseable() {
        CertifyException ex = assertThrows(CertifyException.class,
                () -> resolver.resolve("not-a-date", "2031-07-24T06:30:00Z"));
        assertEquals(ErrorConstants.INVALID_CREDENTIAL_VALIDITY, ex.getErrorCode());
    }
}
