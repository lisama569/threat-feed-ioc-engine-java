package com.github.lisama569.iocengine.model;

import java.time.Instant;

/**
 * One normalized indicator observation from a single source.
 * Immutable; merging happens in the store.
 */
public record IocRecord(
        IocType type,
        String value,        // normalized (lowercased where applicable)
        String source,
        int confidence,      // 0..100
        Instant firstSeen,
        Instant expiresAt,   // null means never expires
        String batchId
) {
    public boolean isExpired(Instant now) {
        return expiresAt != null && !expiresAt.isAfter(now);
    }
}
