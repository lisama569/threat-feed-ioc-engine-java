package com.github.lisama569.threatfeediocenginejava.ioc.fp;

import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.model.Suppression;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.FeedParser;
import com.github.lisama569.threatfeediocenginejava.ioc.store.IndicatorStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Business point: false-positive marking, reason/expiry, auto-recovery, revocation. */
class FalsePositiveServiceTest {

    private static final Logger log = LoggerFactory.getLogger(FalsePositiveServiceTest.class);

    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-01T00:00:00Z"));
    private final IndicatorStore store = new IndicatorStore(List.of("feedA"));
    private final FalsePositiveService fp = new FalsePositiveService(store, clock);

    private void ingestIp(String value, String validUntil) {
        String raw = "[{\"type\":\"ip\",\"value\":\"" + value + "\",\"source\":\"feedA\","
                + "\"confidence\":90,\"validUntil\":\"" + validUntil + "\"}]";
        store.ingest("b-" + value, new FeedParser().parse(raw, "b-" + value));
    }

    @Test
    void markedIndicatorIsSuppressedAndCarriesReasonAndWindow() {
        ingestIp("5.5.5.5", "2027-01-01T00:00:00Z");
        Suppression s = fp.suppress(IndicatorType.IP, "5.5.5.5",
                "known NAT egress", Instant.parse("2026-10-08T00:00:00Z"));
        log.info("suppressed 5.5.5.5: {}", s);
        assertEquals("known NAT egress", s.reason());
        assertEquals(Instant.parse("2026-10-08T00:00:00Z"), s.expiresAt());
        assertFalse(s.isRevoked());

        Optional<Suppression> current =
                store.currentSuppression(IndicatorType.IP, "5.5.5.5", clock.instant());
        assertTrue(current.isPresent());
        assertTrue(current.get().isActiveAt(clock.instant()));
    }

    @Test
    void suppressionAutoRecoversAfterExpiry() {
        ingestIp("6.6.6.6", "2027-01-01T00:00:00Z");
        fp.suppress(IndicatorType.IP, "6.6.6.6", "temporary FP",
                Instant.parse("2026-10-05T00:00:00Z"));
        assertTrue(store.currentSuppression(IndicatorType.IP, "6.6.6.6", clock.instant()).isPresent());

        // just before expiry: still active
        clock.set(Instant.parse("2026-10-04T23:59:59Z"));
        assertTrue(store.currentSuppression(IndicatorType.IP, "6.6.6.6", clock.instant()).isPresent());

        // at/after expiry instant (half-open): auto recovered, no explicit cleanup
        clock.set(Instant.parse("2026-10-05T00:00:00Z"));
        assertFalse(store.currentSuppression(IndicatorType.IP, "6.6.6.6", clock.instant()).isPresent());
        assertTrue(store.lookup(IndicatorType.IP, "6.6.6.6", clock.instant()).isPresent(),
                "intel itself remains, only the suppression lapsed");
        log.info("after expiry intel lookup restored -> live hit again");
    }

    @Test
    void revokeCancelsSuppressionImmediately() {
        ingestIp("7.7.7.7", "2027-01-01T00:00:00Z");
        fp.suppress(IndicatorType.IP, "7.7.7.7", "fp",
                Instant.parse("2026-11-01T00:00:00Z"));
        boolean revoked = fp.revoke(IndicatorType.IP, "7.7.7.7");
        log.info("revoke result={}", revoked);
        assertTrue(revoked);
        assertFalse(store.currentSuppression(IndicatorType.IP, "7.7.7.7", clock.instant()).isPresent());

        // revoking again / unknown indicator -> false, no error
        assertFalse(fp.revoke(IndicatorType.IP, "7.7.7.7"));
        assertFalse(fp.revoke(IndicatorType.IP, "9.9.9.9"));
    }

    @Test
    void rejectsBlankReasonPastExpiryAndInvalidValue() {
        assertThrows(IllegalArgumentException.class, () ->
                fp.suppress(IndicatorType.IP, "5.5.5.5", "  ",
                        Instant.parse("2026-11-01T00:00:00Z")));
        assertThrows(IllegalArgumentException.class, () ->
                fp.suppress(IndicatorType.IP, "5.5.5.5", "reason",
                        Instant.parse("2026-09-01T00:00:00Z")));
        assertThrows(IllegalArgumentException.class, () ->
                fp.suppress(IndicatorType.IP, "not-an-ip", "reason",
                        Instant.parse("2026-11-01T00:00:00Z")));
        assertThrows(IllegalArgumentException.class, () ->
                fp.suppress(IndicatorType.IP, "5.5.5.5", "reason", null));
        log.info("invalid suppression requests rejected");
    }

    @Test
    void remarkingReplacesPreviousSuppression() {
        ingestIp("8.8.8.8", "2027-01-01T00:00:00Z");
        fp.suppress(IndicatorType.IP, "8.8.8.8", "old reason",
                Instant.parse("2026-10-03T00:00:00Z"));
        Suppression updated = fp.suppress(IndicatorType.IP, "8.8.8.8", "new reason",
                Instant.parse("2026-12-01T00:00:00Z"));
        Suppression current =
                store.currentSuppression(IndicatorType.IP, "8.8.8.8", clock.instant()).orElseThrow();
        log.info("replaced suppression -> {}", current);
        assertEquals("new reason", current.reason());
        assertEquals(updated.expiresAt(), current.expiresAt());
    }

    /** A mutable clock so tests can move time forward deterministically. */
    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void set(Instant t) {
            this.now = t;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
