package com.github.lisama569.threatfeediocenginejava.ioc.fp;

import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.model.Suppression;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.FeedParser;
import com.github.lisama569.threatfeediocenginejava.ioc.store.IndicatorStore;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/**
 * Analyst false-positive (allow-list) workflow on top of the indicator store.
 *
 * <p>A suppression applies to one canonical (type, value), carries a required
 * analyst reason and an explicit expiry instant. It stops suppressing at the
 * expiry instant (half-open window) — detection then automatically returns to
 * normal with no cleanup job — and an analyst can revoke it early.
 *
 * <p>Re-marking an indicator replaces the previous suppression (new reason /
 * expiry). Suppression state is stored inside {@link IndicatorStore} and read
 * together with intel under the same lock, so concurrent ingest + detect never
 * exposes an intermediate verdict.
 */
public class FalsePositiveService {

    private final IndicatorStore store;
    private final Clock clock;

    public FalsePositiveService(IndicatorStore store, Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Mark an indicator as a false positive until {@code expiresAt}.
     *
     * @throws IllegalArgumentException for an unsupported/invalid type/value,
     *                                  blank reason, or expiry not in the future
     */
    public Suppression suppress(IndicatorType type, String value, String reason, Instant expiresAt) {
        IndicatorType t = requireType(type);
        String normalized = requireValue(t, value);
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be blank");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt is required");
        }
        Instant now = clock.instant();
        if (!expiresAt.isAfter(now)) {
            throw new IllegalArgumentException("expiresAt must be in the future: " + expiresAt);
        }
        Suppression s = Suppression.create(reason.trim(), now, expiresAt);
        return store.putSuppression(t, normalized, s);
    }

    /** Revoke an active suppression immediately. Returns false when none is active. */
    public boolean revoke(IndicatorType type, String value) {
        IndicatorType t = requireType(type);
        String normalized = requireValue(t, value);
        return store.revokeSuppression(t, normalized, clock.instant());
    }

    private static IndicatorType requireType(IndicatorType type) {
        if (type == null) {
            throw new IllegalArgumentException("indicator type is required");
        }
        return type;
    }

    private static String requireValue(IndicatorType type, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("indicator value is required");
        }
        String normalized = FeedParser.normalize(type, value.trim());
        if (normalized == null) {
            throw new IllegalArgumentException(
                    "value '" + value + "' is not a valid " + type);
        }
        return normalized;
    }
}
