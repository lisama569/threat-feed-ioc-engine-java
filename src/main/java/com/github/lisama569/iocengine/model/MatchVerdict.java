package com.github.lisama569.iocengine.model;

import java.time.Instant;

/**
 * Verdict for one indicator extracted from an event.
 *
 * @param hit        whether a live (non-expired) indicator matched
 * @param type       indicator type
 * @param value      normalized indicator value
 * @param source     winning source (null on miss)
 * @param confidence winning confidence (null on miss)
 * @param expiresAt  winning expiry (null on miss or never-expiring)
 * @param explanation human-readable justification of the decision
 */
public record MatchVerdict(
        boolean hit,
        IocType type,
        String value,
        String source,
        Integer confidence,
        Instant expiresAt,
        String explanation
) {
    public static MatchVerdict miss(IocType type, String value, String explanation) {
        return new MatchVerdict(false, type, value, null, null, null, explanation);
    }
}
