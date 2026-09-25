package com.github.lisama569.iocengine;

import com.github.lisama569.iocengine.model.IocRecord;
import com.github.lisama569.iocengine.model.IocType;
import com.github.lisama569.iocengine.store.IocStore;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class IocStoreTest {

    private static final Logger LOG = Logger.getLogger(IocStoreTest.class.getName());
    private static final Instant NOW = Instant.parse("2026-09-26T00:00:00Z");
    private static final Instant FUTURE = Instant.parse("2027-01-01T00:00:00Z");
    private static final Instant PAST = Instant.parse("2026-01-01T00:00:00Z");

    private IocStore storeWithPriorities() {
        return new IocStore(Map.of("internal", 100, "partner", 50));
    }

    private IocRecord rec(String source, int confidence, Instant expiresAt, String batch) {
        return new IocRecord(IocType.IPV4, "203.0.113.10", source, confidence,
                PAST, expiresAt, batch);
    }

    @Test
    void higherPrioritySourceWinsConflict() {
        IocStore store = storeWithPriorities();
        // ingest partner first, internal second: result must not depend on order
        store.merge("b1", List.of(rec("partner", 95, FUTURE, "b1")));
        store.merge("b2", List.of(rec("internal", 10, FUTURE, "b2")));
        Optional<IocRecord> winner = store.lookup(IocType.IPV4, "203.0.113.10", NOW);
        LOG.info("conflict partner(conf=95,prio=50) vs internal(conf=10,prio=100) -> winner=" + winner);
        assertTrue(winner.isPresent());
        assertEquals("internal", winner.get().source()); // priority beats confidence
    }

    @Test
    void samePriorityHigherConfidenceWins() {
        IocStore store = storeWithPriorities();
        store.merge("b1", List.of(rec("feed-x", 40, FUTURE, "b1")));
        store.merge("b2", List.of(rec("feed-y", 80, FUTURE, "b2")));
        Optional<IocRecord> winner = store.lookup(IocType.IPV4, "203.0.113.10", NOW);
        LOG.info("conflict feed-x(conf=40) vs feed-y(conf=80), equal priority -> winner=" + winner);
        assertEquals("feed-y", winner.get().source());
    }

    @Test
    void verdictIsDeterministicRegardlessOfIngestionOrder() {
        List<IocRecord> a = List.of(rec("feed-x", 40, FUTURE, "b1"), rec("feed-y", 80, FUTURE, "b2"));
        IocStore s1 = storeWithPriorities();
        s1.merge("b1", List.of(a.get(0)));
        s1.merge("b2", List.of(a.get(1)));
        IocStore s2 = storeWithPriorities();
        s2.merge("b2", List.of(a.get(1)));
        s2.merge("b1", List.of(a.get(0)));
        String w1 = s1.lookup(IocType.IPV4, "203.0.113.10", NOW).orElseThrow().source();
        String w2 = s2.lookup(IocType.IPV4, "203.0.113.10", NOW).orElseThrow().source();
        LOG.info("order1 winner=" + w1 + " order2 winner=" + w2);
        assertEquals(w1, w2);
    }

    @Test
    void expiredIndicatorNeverMatches() {
        IocStore store = storeWithPriorities();
        store.merge("b1", List.of(rec("internal", 100, PAST, "b1"))); // already expired
        Optional<IocRecord> hit = store.lookup(IocType.IPV4, "203.0.113.10", NOW);
        LOG.info("expired indicator lookup -> " + hit);
        assertTrue(hit.isEmpty());
    }

    @Test
    void expiredWinnerFallsBackToLiveLowerPrioritySource() {
        IocStore store = storeWithPriorities();
        store.merge("b1", List.of(rec("internal", 100, PAST, "b1")));   // expired, high prio
        store.merge("b2", List.of(rec("partner", 50, FUTURE, "b2")));   // live, low prio
        Optional<IocRecord> winner = store.lookup(IocType.IPV4, "203.0.113.10", NOW);
        LOG.info("expired internal + live partner -> winner=" + winner);
        assertTrue(winner.isPresent());
        assertEquals("partner", winner.get().source());
    }

    @Test
    void duplicateBatchIsNoOp() {
        IocStore store = storeWithPriorities();
        List<IocRecord> batch = List.of(rec("internal", 90, FUTURE, "b1"));
        int first = store.merge("b1", batch);
        int second = store.merge("b1", batch);
        LOG.info("first merge=" + first + " second merge=" + second + " store size=" + store.size());
        assertEquals(1, first);
        assertEquals(0, second);           // no duplicate counts
        assertEquals(1, store.size());     // no duplicate state
        assertEquals(1, store.appliedBatchCount());
    }

    @Test
    void sameSourceRereportReplacesOldRecord() {
        IocStore store = storeWithPriorities();
        store.merge("b1", List.of(rec("internal", 90, FUTURE, "b1")));
        store.merge("b2", List.of(rec("internal", 30, FUTURE, "b2")));
        IocRecord winner = store.lookup(IocType.IPV4, "203.0.113.10", NOW).orElseThrow();
        LOG.info("re-report by same source -> confidence=" + winner.confidence());
        assertEquals(30, winner.confidence()); // latest observation wins within a source
    }
}
