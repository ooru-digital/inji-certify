/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * Resolves {@code validFrom} / {@code validUntil} for VC API issuance.
 * Uses client values when both are present; otherwise falls back to now + {@code vc-expiry-duration}.
 */
@Slf4j
@Component
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class VcApiValidityResolver {

    private static final DateTimeFormatter UTC_FORMATTER =
            DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN).withZone(ZoneOffset.UTC);

    @Value("${mosip.certify.data-provider-plugin.vc-expiry-duration:P730D}")
    private String defaultExpiryDuration;

    public ValidityWindow resolve(String validFrom, String validUntil) {
        boolean hasFrom = StringUtils.isNotBlank(validFrom);
        boolean hasUntil = StringUtils.isNotBlank(validUntil);

        if (hasFrom ^ hasUntil) {
            throw new CertifyException(ErrorConstants.INVALID_CREDENTIAL_VALIDITY,
                    "Both validFrom and validUntil must be provided together");
        }

        if (hasFrom) {
            Instant from = parseInstant(validFrom.trim(), VCDM_VALID_FROM);
            Instant until = parseInstant(validUntil.trim(), VCDM_VALID_UNTIL);
            if (!until.isAfter(from)) {
                throw new CertifyException(ErrorConstants.INVALID_EXPIRY_RANGE,
                        "validUntil must be after validFrom");
            }
            return new ValidityWindow(format(from), format(until));
        }

        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        Duration duration = parseExpiryDuration();
        return new ValidityWindow(
                now.format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN)),
                now.plus(duration).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN)));
    }

    private Instant parseInstant(String value, String fieldName) {
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            try {
                return ZonedDateTime.parse(value, DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN)
                        .withZone(ZoneOffset.UTC)).toInstant();
            } catch (DateTimeParseException ex) {
                throw new CertifyException(ErrorConstants.INVALID_CREDENTIAL_VALIDITY,
                        "Invalid ISO-8601 datetime for " + fieldName + ": " + value);
            }
        }
    }

    private String format(Instant instant) {
        return UTC_FORMATTER.format(instant);
    }

    private Duration parseExpiryDuration() {
        try {
            return Duration.parse(defaultExpiryDuration);
        } catch (DateTimeParseException e) {
            log.warn("Incorrect expiry duration format: {}. Using P730D", defaultExpiryDuration);
            return Duration.parse("P730D");
        }
    }

    private static final String VCDM_VALID_FROM = "validFrom";
    private static final String VCDM_VALID_UNTIL = "validUntil";

    public record ValidityWindow(String validFrom, String validUntil) {
    }
}
