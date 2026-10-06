package com.github.lisama569.threatfeediocenginejava.ioc.model;

import java.time.Instant;
import java.util.Objects;

/**
 * An analyst-created false-positive suppression (allow-list entry) for one indicator.
 *
 * @param reason    analyst-provided reason (required)
 * @param createdAt when the suppression was created
 * @param expiresAt when the suppression stops being effective, exclusive (required, after createdAt)
 * @param revokedAt when an analyst revoked it; null while in effect or after natural expiry
 */
public record Suppression(String reason, Instant createdAt, Instant expiresAt, Instant revokedAt) {

    public Suppression {
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be blank");
        }
        if (!expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException("expiresAt must be after createdAt");
        }
    }

    /** Create a fresh, non-revoked suppression. */
    public static Suppression create(String reason, Instant createdAt, Instant expiresAt) {
        return new Suppression(reason, createdAt, expiresAt, null);
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpiredAt(Instant now) {
        return !now.isBefore(expiresAt);
    }

    /** Effective at {@code now}: not revoked and the window [createdAt, expiresAt) contains now. */
    public boolean isActiveAt(Instant now) {
        return !isRevoked() && !now.isBefore(createdAt) && now.isBefore(expiresAt);
    }

    /** Return a copy marked revoked at the given instant. */
    public Suppression revoked(Instant at) {
        return new Suppression(reason, createdAt, expiresAt, at);
    }
}
