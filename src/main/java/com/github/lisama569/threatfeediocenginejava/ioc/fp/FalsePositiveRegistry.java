package com.github.lisama569.threatfeediocenginejava.ioc.fp;

import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe registry of analyst false-positive dispositions.
 *
 * Visibility: a mark/revoke is a single atomic map operation, so a detection
 * running concurrently with ingestion or other dispositions always sees a
 * consistent state — a suppression is either fully visible or not at all,
 * never in an intermediate state.
 *
 * Expiry: a suppression stops applying the instant its validUntil passes
 * (evaluated against the registry clock); expired entries are purged lazily.
 */
public class FalsePositiveRegistry {

    private record Key(IndicatorType type, String value) {
    }

    private final Map<Key, FalsePositiveRecord> suppressions = new ConcurrentHashMap<>();
    private final Clock clock;

    public FalsePositiveRegistry(Clock clock) {
        this.clock = clock;
    }

    /**
     * Mark an indicator as a false positive until the given instant (exclusive).
     * Replaces any previous disposition for the same indicator.
     */
    public FalsePositiveRecord mark(IndicatorType type, String value, String reason, Instant validUntil) {
        FalsePositiveRecord record = new FalsePositiveRecord(
                type, normalize(value), reason, clock.instant(), validUntil);
        suppressions.put(new Key(record.type(), record.value()), record);
        return record;
    }

    /** Revoke an existing suppression; returns true when one was removed. */
    public boolean revoke(IndicatorType type, String value) {
        return suppressions.remove(new Key(type, normalize(value))) != null;
    }

    /** The suppression active at the evaluation instant, if any. */
    public Optional<FalsePositiveRecord> activeSuppression(IndicatorType type, String value, Instant now) {
        Key key = new Key(type, normalize(value));
        FalsePositiveRecord record = suppressions.get(key);
        if (record == null) {
            return Optional.empty();
        }
        if (!record.isActiveAt(now)) {
            suppressions.remove(key, record); // lazy purge, only if still the same entry
            return Optional.empty();
        }
        return Optional.of(record);
    }

    /** Number of currently active (non-expired) suppressions. */
    public int activeCount() {
        Instant now = clock.instant();
        int count = 0;
        for (Map.Entry<Key, FalsePositiveRecord> e : suppressions.entrySet()) {
            if (e.getValue().isActiveAt(now)) {
                count++;
            } else {
                suppressions.remove(e.getKey(), e.getValue());
            }
        }
        return count;
    }

    private static String normalize(String value) {
        return value.trim().toLowerCase(java.util.Locale.ROOT);
    }
}
