package com.github.lisama569.threatfeediocenginejava.ioc.match;

import com.github.lisama569.threatfeediocenginejava.ioc.model.Indicator;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.store.IndicatorStore;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * Matches event fields against the indicator store and explains every verdict.
 * Lookup is an O(1) hash lookup, so match cost does not degrade linearly
 * with the total number of stored indicators.
 */
public class MatchService {

    private final IndicatorStore store;
    private final Clock clock;

    public MatchService(IndicatorStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    /** Match one event field; the result always carries a判定依据 explanation. */
    public MatchResult match(IndicatorType type, String value) {
        return match(type, value, clock.instant());
    }

    /**
     * Match one event field at an explicit evaluation instant, so that a
     * whole event (many indicators) is judged at a single, reproducible time.
     */
    public MatchResult match(IndicatorType type, String value, Instant now) {
        Optional<Indicator> hit = store.lookup(type, value, now);
        if (hit.isEmpty()) {
            return MatchResult.miss(String.format(
                    "no live indicator for %s=%s at %s (unknown or expired)", type, value, now));
        }
        Indicator i = hit.get();
        String explanation = String.format(
                "matched %s=%s | source=%s | confidence=%d | validFrom=%s | validUntil=%s | evaluatedAt=%s",
                i.type(), i.value(), i.source(), i.confidence(),
                i.validFrom() == null ? "-inf" : i.validFrom().toString(),
                i.validUntil() == null ? "+inf" : i.validUntil().toString(),
                now);
        return MatchResult.hit(i, explanation);
    }
}
