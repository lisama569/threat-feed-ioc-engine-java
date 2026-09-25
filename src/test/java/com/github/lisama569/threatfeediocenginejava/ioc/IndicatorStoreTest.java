package com.github.lisama569.threatfeediocenginejava.ioc;

import com.github.lisama569.threatfeediocenginejava.ioc.model.Indicator;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IngestionResult;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.FeedParser;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.ParsedFeed;
import com.github.lisama569.threatfeediocenginejava.ioc.store.IndicatorStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IndicatorStoreTest {

    private static final Logger log = LoggerFactory.getLogger(IndicatorStoreTest.class);
    private static final Instant NOW = Instant.parse("2026-09-26T00:00:00Z");

    private final FeedParser parser = new FeedParser();

    private IndicatorStore newStore() {
        // feedA > feedB > feedC; unlisted sources rank lowest
        return new IndicatorStore(List.of("feedA", "feedB", "feedC"));
    }

    @Test
    void higherPrioritySourceWinsConflict() {
        IndicatorStore store = newStore();
        String feedB = "[{\"type\":\"ip\",\"value\":\"1.2.3.4\",\"source\":\"feedB\",\"confidence\":95}]";
        String feedA = "[{\"type\":\"ip\",\"value\":\"1.2.3.4\",\"source\":\"feedA\",\"confidence\":40}]";
        store.ingest("batch-b", parser.parse(feedB, "batch-b"));
        store.ingest("batch-a", parser.parse(feedA, "batch-a"));
        Optional<Indicator> hit = store.lookup(IndicatorType.IP, "1.2.3.4", NOW);
        log.info("conflict feedA(conf=40,prio=high) vs feedB(conf=95,prio=low) -> winner={}", hit);
        assertTrue(hit.isPresent());
        assertEquals("feedA", hit.get().source(),
                "source priority beats confidence");
    }

    @Test
    void conflictResolutionIsOrderIndependentAndReproducible() {
        String feedA = "[{\"type\":\"domain\",\"value\":\"evil.example.com\",\"source\":\"feedA\",\"confidence\":40}]";
        String feedB = "[{\"type\":\"domain\",\"value\":\"evil.example.com\",\"source\":\"feedB\",\"confidence\":95}]";
        // ingest in both orders; the verdict must be identical
        IndicatorStore s1 = newStore();
        s1.ingest("a1", parser.parse(feedA, "a1"));
        s1.ingest("b1", parser.parse(feedB, "b1"));
        IndicatorStore s2 = newStore();
        s2.ingest("b1", parser.parse(feedB, "b1"));
        s2.ingest("a1", parser.parse(feedA, "a1"));
        Indicator w1 = s1.lookup(IndicatorType.DOMAIN, "evil.example.com", NOW).orElseThrow();
        Indicator w2 = s2.lookup(IndicatorType.DOMAIN, "evil.example.com", NOW).orElseThrow();
        log.info("order1 winner={} | order2 winner={}", w1, w2);
        assertEquals(w1.source(), w2.source());
        assertEquals(w1.confidence(), w2.confidence());
    }

    @Test
    void sameSourceHigherConfidenceWins() {
        IndicatorStore store = newStore();
        store.ingest("c1", parser.parse(
                "[{\"type\":\"ip\",\"value\":\"9.9.9.9\",\"source\":\"feedA\",\"confidence\":10}]", "c1"));
        store.ingest("c2", parser.parse(
                "[{\"type\":\"ip\",\"value\":\"9.9.9.9\",\"source\":\"feedA\",\"confidence\":90}]", "c2"));
        Indicator w = store.lookup(IndicatorType.IP, "9.9.9.9", NOW).orElseThrow();
        log.info("same source conf 10 vs 90 -> winner={}", w);
        assertEquals(90, w.confidence());
    }

    @Test
    void expiredIndicatorNeverMatches() {
        IndicatorStore store = newStore();
        String raw = "[{\"type\":\"ip\",\"value\":\"5.6.7.8\",\"source\":\"feedA\","
                + "\"validUntil\":\"2026-01-01T00:00:00Z\"}]";
        store.ingest("exp1", parser.parse(raw, "exp1"));
        Optional<Indicator> hit = store.lookup(IndicatorType.IP, "5.6.7.8", NOW);
        log.info("expired indicator lookup at {} -> {}", NOW, hit);
        assertTrue(hit.isEmpty(), "expired indicator must not be hit");
    }

    @Test
    void notYetValidIndicatorNeverMatches() {
        IndicatorStore store = newStore();
        String raw = "[{\"type\":\"ip\",\"value\":\"5.6.7.9\",\"source\":\"feedA\","
                + "\"validFrom\":\"2027-01-01T00:00:00Z\"}]";
        store.ingest("fut1", parser.parse(raw, "fut1"));
        assertTrue(store.lookup(IndicatorType.IP, "5.6.7.9", NOW).isEmpty());
    }

    @Test
    void reimportingSameBatchIsIdempotent() {
        IndicatorStore store = newStore();
        String raw = "[{\"type\":\"ip\",\"value\":\"2.2.2.2\",\"source\":\"feedA\",\"confidence\":70}]";
        ParsedFeed feed = parser.parse(raw, "same-batch");
        IngestionResult first = store.ingest("same-batch", feed);
        IngestionResult second = store.ingest("same-batch", feed);
        log.info("first={} second={} storeSize={}", first, second, store.size());
        assertEquals(1, first.accepted());
        assertEquals(0, first.duplicates());
        assertEquals(0, second.accepted(), "re-import must not add state");
        assertEquals(1, second.duplicates(), "re-import must be counted as duplicate");
        assertEquals(1, store.size(), "no duplicate state");
    }

    @Test
    void supersededCountReflectsReplacement() {
        IndicatorStore store = newStore();
        IngestionResult r1 = store.ingest("s1", parser.parse(
                "[{\"type\":\"ip\",\"value\":\"3.3.3.3\",\"source\":\"feedC\",\"confidence\":50}]", "s1"));
        IngestionResult r2 = store.ingest("s2", parser.parse(
                "[{\"type\":\"ip\",\"value\":\"3.3.3.3\",\"source\":\"feedA\",\"confidence\":50}]", "s2"));
        log.info("r1={} r2={}", r1, r2);
        assertEquals(0, r1.superseded());
        assertEquals(1, r2.superseded(), "higher-priority record replaces the visible winner");
        assertEquals("feedA", store.lookup(IndicatorType.IP, "3.3.3.3", NOW).orElseThrow().source());
    }
}
