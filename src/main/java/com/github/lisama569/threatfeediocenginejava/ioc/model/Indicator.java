package com.github.lisama569.threatfeediocenginejava.ioc.model;

import java.time.Instant;
import java.util.Objects;

/**
 * A normalized, validated indicator ready for storage.
 *
 * @param type       indicator type
 * @param value      normalized indicator value (canonical form)
 * @param source     originating feed/source identifier
 * @param confidence confidence in [0, 100]
 * @param validFrom  start of validity window (nullable = always valid)
 * @param validUntil end of validity window, exclusive (nullable = never expires)
 * @param batchId    ingestion batch identifier, used for idempotent re-import
 */
public record Indicator(IndicatorType type, String value, String source, int confidence,
                        Instant validFrom, Instant validUntil, String batchId) {

    public Indicator {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(batchId, "batchId");
        if (confidence < 0 || confidence > 100) {
            throw new IllegalArgumentException("confidence out of range: " + confidence);
        }
    }

    /** Identity used for idempotent dedup: same indicator re-imported in the same batch. */
    public String dedupKey() {
        return type + "|" + value + "|" + source + "|" + batchId;
    }

    /** Whether this indicator is live at the given instant. */
    public boolean isLiveAt(Instant now) {
        if (validFrom != null && now.isBefore(validFrom)) {
            return false;
        }
        return validUntil == null || now.isBefore(validUntil);
    }
}
