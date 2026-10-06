package com.github.lisama569.threatfeediocenginejava.ioc.event;

import com.github.lisama569.threatfeediocenginejava.ioc.fp.FalsePositiveService;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.FeedParser;
import com.github.lisama569.threatfeediocenginejava.ioc.store.IndicatorStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Business points for raw-event detection:
 * multi-indicator events, repeated indicator counted once, no-indicator events,
 * multi-source with partial expiry, suppressed hits, expiry auto-recovery,
 * batch ordering, and deterministic reproducibility.
 */
class EventDetectionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(EventDetectionServiceTest.class);
    private static final Instant NOW = Instant.parse("2026-10-01T12:00:00Z");

    private final FeedParser parser = new FeedParser();
    private final IndicatorStore store = new IndicatorStore(List.of("feedA", "feedB"));
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final EventDetectionService detector =
            new EventDetectionService(new IocExtractor(), store, clock);
    private final FalsePositiveService fp = new FalsePositiveService(store, clock);

    private void ingest(String batchId, String json) {
        store.ingest(batchId, parser.parse(json, batchId));
    }

    @Test
    void eventWithMultipleIndicatorsReturnsVerdictPerDistinctIndicator() {
        ingest("b1", """
                [
                  {"type":"ip","value":"198.51.100.10","source":"feedA","confidence":90,
                   "validUntil":"2027-01-01T00:00:00Z"},
                  {"type":"domain","value":"evil.example.com","source":"feedB","confidence":70,
                   "validUntil":"2027-01-01T00:00:00Z"}
                ]
                """);
        String event = "host 198.51.100.10 beaconed to evil.example.com repeatedly";
        EventDetectionResult r = detector.detect(event);
        r.verdicts().forEach(v -> log.info("[multi] {} {}={} | {}",
                v.status(), v.type(), v.value(), v.explanation()));
        assertEquals(EventConclusion.THREAT_DETECTED, r.conclusion());
        assertEquals(2, r.extracted());
        assertEquals(2, r.hits());
        assertEquals(0, r.suppressed());
    }

    @Test
    void sameIndicatorRepeatedInOneEventIsHitOnlyOnce() {
        ingest("b2", "[{\"type\":\"ip\",\"value\":\"198.51.100.20\",\"source\":\"feedA\","
                + "\"validUntil\":\"2027-01-01T00:00:00Z\"}]");
        String event = "198.51.100.20 -> 198.51.100.20 -> 198.51.100.20";
        EventDetectionResult r = detector.detect(event);
        log.info("[repeat] extracted={} hits={} verdicts={}",
                r.extracted(), r.hits(), r.verdicts().size());
        assertEquals(1, r.extracted(), "repeated indicator extracted once");
        assertEquals(1, r.hits(), "repeated indicator produces a single hit");
        assertEquals(1, r.verdicts().size());
    }

    @Test
    void eventWithoutDetectableIndicatorsIsExplicitlyReported() {
        EventDetectionResult r = detector.detect("nothing interesting here, just prose.");
        log.info("[none] conclusion={} verdicts={}", r.conclusion(), r.verdicts().size());
        assertEquals(EventConclusion.NO_DETECTABLE_INDICATORS, r.conclusion());
        assertEquals(0, r.extracted());
        assertEquals(0, r.hits());
        assertNotNull(r.verdicts(), "must return a populated result, never null/empty body");

        EventDetectionResult empty = detector.detect("");
        assertEquals(EventConclusion.NO_DETECTABLE_INDICATORS, empty.conclusion());
        EventDetectionResult nullText = detector.detect((String) null);
        assertEquals(EventConclusion.NO_DETECTABLE_INDICATORS, nullText.conclusion());
    }

    @Test
    void indicatorsPresentButUnknownOrExpiredYieldNoMatch() {
        ingest("b3", "[{\"type\":\"ip\",\"value\":\"198.51.100.30\",\"source\":\"feedA\","
                + "\"validUntil\":\"2026-09-01T00:00:00Z\"}]"); // expired before NOW
        EventDetectionResult r = detector.detect("expired IOC seen: 198.51.100.30; unknown: 192.0.2.55");
        r.verdicts().forEach(v -> log.info("[nomatch] {} {}={} | {}",
                v.status(), v.type(), v.value(), v.explanation()));
        assertEquals(EventConclusion.NO_MATCH, r.conclusion());
        assertEquals(2, r.extracted());
        assertEquals(0, r.hits());
        r.verdicts().forEach(v -> assertEquals(IndicatorVerdict.Status.MISS, v.status()));
    }

    @Test
    void partiallyExpiredMultiSourceLandsStablyOnTheLiveRecord() {
        // feedA higher priority but EXPIRED; feedB lower priority still live
        ingest("b4a", "[{\"type\":\"domain\",\"value\":\"dual.example.com\",\"source\":\"feedA\","
                + "\"confidence\":99,\"validUntil\":\"2026-09-01T00:00:00Z\"}]");
        ingest("b4b", "[{\"type\":\"domain\",\"value\":\"dual.example.com\",\"source\":\"feedB\","
                + "\"confidence\":40,\"validUntil\":\"2027-01-01T00:00:00Z\"}]");
        EventDetectionResult r = detector.detect("callback to dual.example.com");
        IndicatorVerdict v = r.verdicts().get(0);
        log.info("[partial-expiry] {} source={} conf={} | {}",
                v.status(), v.indicator().source(), v.indicator().confidence(), v.explanation());
        assertEquals(IndicatorVerdict.Status.HIT, v.status(),
                "an expired record must not turn the event into a miss");
        assertEquals("feedB", v.indicator().source(), "verdict lands on the still-live source");
        assertTrue(v.explanation().contains("validUntil=2027-01-01T00:00:00Z"));
        assertTrue(v.explanation().contains("source=feedB"));
    }

    @Test
    void allSourcesExpiredNeverHits() {
        ingest("b5a", "[{\"type\":\"ip\",\"value\":\"203.0.113.77\",\"source\":\"feedA\","
                + "\"validUntil\":\"2026-09-01T00:00:00Z\"}]");
        ingest("b5b", "[{\"type\":\"ip\",\"value\":\"203.0.113.77\",\"source\":\"feedB\","
                + "\"validUntil\":\"2026-09-15T00:00:00Z\"}]");
        EventDetectionResult r = detector.detect("203.0.113.77");
        log.info("[all-expired] {} hits={}", r.conclusion(), r.hits());
        assertEquals(EventConclusion.NO_MATCH, r.conclusion());
        assertEquals(0, r.hits());
    }

    @Test
    void suppressedHitIsVisibleAsSuppressedNotDropped() {
        ingest("b6", "[{\"type\":\"domain\",\"value\":\"ok.example.com\",\"source\":\"feedA\","
                + "\"confidence\":90,\"validUntil\":\"2027-01-01T00:00:00Z\"}]");
        fp.suppress(IndicatorType.DOMAIN, "ok.example.com",
                "internal monitoring domain", Instant.parse("2026-10-10T00:00:00Z"));
        EventDetectionResult r = detector.detect("alert on ok.example.com");
        IndicatorVerdict v = r.verdicts().get(0);
        log.info("[suppressed] {} | {}", v.status(), v.explanation());
        assertEquals(IndicatorVerdict.Status.SUPPRESSED_HIT, v.status(),
                "a suppressed hit must remain distinguishable, not disappear");
        assertNotNull(v.indicator(), "original intel retained on a suppressed hit");
        assertNotNull(v.suppression());
        assertEquals("internal monitoring domain", v.suppression().reason());
        assertTrue(v.explanation().contains("SUPPRESSED as false positive"));
        assertEquals(EventConclusion.ALL_HITS_SUPPRESSED, r.conclusion());
        assertEquals(1, r.hits());
        assertEquals(1, r.suppressed());
    }

    @Test
    void mixedSuppressedAndLiveHitsStillConcludeThreat() {
        ingest("b7", """
                [
                  {"type":"domain","value":"white.example.com","source":"feedA",
                   "validUntil":"2027-01-01T00:00:00Z"},
                  {"type":"ip","value":"198.51.100.77","source":"feedA",
                   "validUntil":"2027-01-01T00:00:00Z"}
                ]
                """);
        fp.suppress(IndicatorType.DOMAIN, "white.example.com",
                "false positive", Instant.parse("2026-10-10T00:00:00Z"));
        EventDetectionResult r = detector.detect(
                "white.example.com and 198.51.100.77 both observed");
        log.info("[mixed] conclusion={} hits={} suppressed={}",
                r.conclusion(), r.hits(), r.suppressed());
        assertEquals(EventConclusion.THREAT_DETECTED, r.conclusion(),
                "one remaining live hit keeps the whole event a threat");
        assertEquals(2, r.hits());
        assertEquals(1, r.suppressed());
    }

    @Test
    void suppressionExpiryRestoresNormalHit() {
        MutableClock moving = new MutableClock(NOW);
        IndicatorStore s = new IndicatorStore(List.of("feedA"));
        FalsePositiveService fp2 = new FalsePositiveService(s, moving);
        EventDetectionService det2 = new EventDetectionService(new IocExtractor(), s, moving);
        s.ingest("b8", parser.parse(
                "[{\"type\":\"ip\",\"value\":\"10.0.0.9\",\"source\":\"feedA\","
                        + "\"validUntil\":\"2027-01-01T00:00:00Z\"}]", "b8"));
        fp2.suppress(IndicatorType.IP, "10.0.0.9", "temp",
                Instant.parse("2026-10-03T00:00:00Z"));
        assertEquals(IndicatorVerdict.Status.SUPPRESSED_HIT,
                det2.detect("10.0.0.9").verdicts().get(0).status());
        moving.set(Instant.parse("2026-10-03T00:00:00Z")); // expiry instant
        EventDetectionResult after = det2.detect("10.0.0.9");
        log.info("[recover] {} | {}", after.verdicts().get(0).status(),
                after.verdicts().get(0).explanation());
        assertEquals(IndicatorVerdict.Status.HIT, after.verdicts().get(0).status());
        assertEquals(EventConclusion.THREAT_DETECTED, after.conclusion());
        assertNull(after.verdicts().get(0).suppression());
    }

    @Test
    void batchKeepsOrderAndReportsEachEventIndependently() {
        ingest("b9", "[{\"type\":\"ip\",\"value\":\"198.51.100.200\",\"source\":\"feedA\","
                + "\"validUntil\":\"2027-01-01T00:00:00Z\"}]");
        BatchDetectionRequest req = new BatchDetectionRequest(List.of(
                new BatchDetectionRequest.EventItem("e1", "hit 198.51.100.200"),
                new BatchDetectionRequest.EventItem("e2", "plain text only"),
                new BatchDetectionRequest.EventItem("e3", "unknown 192.0.2.200")));
        List<EventDetectionResult> results = detector.detectBatch(req.events());
        results.forEach(r -> log.info("[batch] {} -> {} (extracted={}, hits={})",
                r.eventId(), r.conclusion(), r.extracted(), r.hits()));
        assertEquals(3, results.size());
        assertEquals("e1", results.get(0).eventId());
        assertEquals(EventConclusion.THREAT_DETECTED, results.get(0).conclusion());
        assertEquals(EventConclusion.NO_DETECTABLE_INDICATORS, results.get(1).conclusion());
        assertEquals(EventConclusion.NO_MATCH, results.get(2).conclusion());
    }

    @Test
    void sameEventDetectedTwiceYieldsIdenticalVerdicts() {
        ingest("b10", "[{\"type\":\"domain\",\"value\":\"rep.example.com\",\"source\":\"feedA\","
                + "\"validUntil\":\"2027-01-01T00:00:00Z\"}]");
        String event = "repeated job sees rep.example.com";
        EventDetectionResult r1 = detector.detect(event);
        EventDetectionResult r2 = detector.detect(event);
        assertEquals(r1.conclusion(), r2.conclusion());
        assertEquals(r1.verdicts().size(), r2.verdicts().size());
        for (int i = 0; i < r1.verdicts().size(); i++) {
            assertEquals(r1.verdicts().get(i).status(), r2.verdicts().get(i).status());
            assertEquals(r1.verdicts().get(i).explanation(), r2.verdicts().get(i).explanation());
        }
        log.info("[repro] identical conclusions: {}", r1.conclusion());
    }

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
