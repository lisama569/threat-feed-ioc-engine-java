package com.github.lisama569.iocengine;

import com.github.lisama569.iocengine.match.IocMatcher;
import com.github.lisama569.iocengine.model.IocRecord;
import com.github.lisama569.iocengine.model.IocType;
import com.github.lisama569.iocengine.store.IocStore;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Matching does hash lookups per extracted indicator, so match latency must be
 * roughly independent of the total number of stored indicators (unlike a
 * linear scan, which would degrade proportionally to feed size).
 */
class PerformanceTest {

    private static final Logger LOG = Logger.getLogger(PerformanceTest.class.getName());
    private static final Instant NOW = Instant.parse("2026-09-26T00:00:00Z");
    private static final int EVENTS = 500;

    private IocStore buildStore(int n) {
        IocStore store = new IocStore(Map.of("internal", 100));
        List<IocRecord> recs = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            recs.add(new IocRecord(IocType.IPV4,
                    "10." + (i >> 16 & 255) + "." + (i >> 8 & 255) + "." + (i & 255),
                    "internal", 80, NOW, NOW.plusSeconds(86400), "bulk"));
        }
        store.merge("bulk", recs);
        return store;
    }

    private List<String> buildEvents(int n) {
        List<String> events = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            // hit an existing indicator plus a miss
            events.add("fw src=192.0.2." + (i % 250)
                    + " dst=10." + ((i * 7) >> 16 & 255) + "." + ((i * 7) >> 8 & 255) + "." + ((i * 7) & 255));
        }
        return events;
    }

    private long timeMatching(IocStore store, List<String> events) {
        IocMatcher matcher = new IocMatcher(store, Clock.fixed(NOW, ZoneOffset.UTC));
        // warmup
        for (int i = 0; i < 100; i++) {
            matcher.match(events.get(i % events.size()));
        }
        long start = System.nanoTime();
        long hits = 0;
        for (String e : events) {
            hits += matcher.match(e).stream().filter(v -> v.hit()).count();
        }
        long elapsed = System.nanoTime() - start;
        LOG.info("storeSize=" + store.size() + " events=" + events.size()
                + " hits=" + hits + " elapsedMs=" + elapsed / 1_000_000);
        return elapsed;
    }

    @Test
    void matchLatencyDoesNotDegradeLinearlyWithFeedSize() {
        List<String> events = buildEvents(EVENTS);
        long small = timeMatching(buildStore(20_000), events);
        long large = timeMatching(buildStore(200_000), events); // 10x the indicators

        double ratio = (double) large / Math.max(small, 1);
        LOG.info("smallStoreNs=" + small + " largeStoreNs=" + large + " ratio=" + ratio);

        // A linear scan would be ~10x slower on 10x data. Hash lookup should be
        // far below that; allow generous headroom for JIT/GC noise.
        assertTrue(ratio < 5.0,
                "matching degraded too much with 10x feed size: ratio=" + ratio);
        // Absolute sanity bound: 500 events against 200k indicators must be fast.
        assertTrue(large < 5_000_000_000L, "matching too slow in absolute terms");
    }
}
