package com.github.lisama569.threatfeediocenginejava.ioc.fp;

import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;

import java.time.Instant;
import java.util.Objects;

/**
 * An analyst's false-positive disposition for one indicator.
 *
 * @param type       indicator type
 * @param value      normalized indicator value
 * @param reason     analyst-supplied justification (required)
 * @param markedAt   when the disposition was recorded
 * @param validUntil when the suppression expires; the indicator then reverts
 *                   to normal verdicts automatically (required)
 */
public record FalsePositiveRecord(IndicatorType type, String value, String reason,
                                  Instant markedAt, Instant validUntil) {

    public FalsePositiveRecord {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(markedAt, "markedAt");
        Objects.requireNonNull(validUntil, "validUntil");
        if (reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be blank");
        }
    }

    /** Whether this suppression is still in effect at the given instant. */
    public boolean isActiveAt(Instant now) {
        return now.isBefore(validUntil);
    }
}
