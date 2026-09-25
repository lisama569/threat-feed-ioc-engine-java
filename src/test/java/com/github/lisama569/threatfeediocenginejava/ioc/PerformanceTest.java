package com.github.lisama569.threatfeediocenginejava.ioc;

import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchResult;
import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchService;
import com.github.lisama569.threatfeediocenginejava.ioc.model.Indicator;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.FeedParser;
import com.github.lisama569.threatfeediocenginejava.ioc.store.IndicatorStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Match cost must be far better than a linear scan and must not degrade
 * linearly as the total number of stored indicators grows.
 */
class PerformanceTest {

    private static final Logger log = LoggerFactory.getLogger(PerformanceTest.class);
    private static final int QUERIES = 20_000;

    private IndicatorStore buildStore(int n) {
        IndicatorStore store = new IndicatorStore(List.of("feedA"));
        FeedParser parser = new FeedParser();
        int batch = 0;
        List<String> records = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            records.add("{\"type\":\"ip\",\"value\":\"10." + (i / 65536) + "."
                    + ((i / 256) % 256) + "." + (i % 256) + "\",\"source\":\"feedA\"}");
            if (records.size() == 10_000) {
                String batchId = "perf-" + (batch++);
                store.ingest(batchId, parser.parse("[" + String.join(",", records) + "]", batchId));
                records.clear();
            }
        }
        if (!records.isEmpty()) {
            String batchId = "perf-" + batch;
            store.ingest(batchId, parser.parse("[" + String.join(",", records) + "]", batchId));
        }
        return store;
    }

    private long timeMatches(MatchService matcher, int queries) {
        long start = System.nanoTime();
        int hits = 0;
        for (int q = 0; q < queries; q++) {
            String value = "10.1." + (q % 256) + "." + (q % 256);
            MatchResult r = matcher.match(IndicatorType.IP, value);
            if (r.matched()) {
                hits++;
            }
        }
        log.info("hits={}/{}", hits, queries);
        return System.nanoTime() - start;
    }

    @Test
    void hashLookupBeatsLinearScanAndDoesNotDegradeLinearly() {
        int small = 10_000;
        int large = 100_000;

        IndicatorStore smallStore = buildStore(small);
        IndicatorStore largeStore = buildStore(large);
        assertEquals(small, smallStore.size());
        assertEquals(large, largeStore.size());

        Clock clock = Clock.fixed(Instant.parse("2026-09-26T00:00:00Z"), ZoneOffset.UTC);
        MatchService smallMatcher = new MatchService(smallStore, clock);
        MatchService largeMatcher = new MatchService(largeStore, clock);

        // warmup
        timeMatches(smallMatcher, 5_000);
        timeMatches(largeMatcher, 5_000);

        long smallNs = timeMatches(smallMatcher, QUERIES);
        long largeNs = timeMatches(largeMatcher, QUERIES);

        // baseline: linear scan over the large store's indicators
        List<Indicator> all = new ArrayList<>();
        for (int i = 0; i < large; i++) {
            all.add(new Indicator(IndicatorType.IP,
                    "10." + (i / 65536) + "." + ((i / 256) % 256) + "." + (i % 256),
                    "feedA", 50, null, null, "baseline"));
        }
        Instant now = clock.instant();
        long scanStart = System.nanoTime();
        int scanHits = 0;
        for (int q = 0; q < QUERIES; q++) {
            String value = "10.1." + (q % 256) + "." + (q % 256);
            for (Indicator ind : all) {
                if (ind.value().equals(value) && ind.isLiveAt(now)) {
                    scanHits++;
                    break;
                }
            }
        }
        long scanNs = System.nanoTime() - scanStart;

        double perQuerySmall = smallNs / (double) QUERIES;
        double perQueryLarge = largeNs / (double) QUERIES;
        log.info("hash match: {} indicators -> {} ns/query; {} indicators -> {} ns/query; "
                        + "linear scan over {} -> {} ns/query (hits={})",
                small, (long) perQuerySmall, large, (long) perQueryLarge,
                large, scanNs / (double) QUERIES, scanHits);

        assertTrue(largeNs < scanNs / 10,
                "hash lookup must be at least 10x faster than linear scan");
        // 10x more data must NOT make per-query cost 10x worse; allow generous headroom
        assertTrue(perQueryLarge < perQuerySmall * 3 + 2_000,
                "per-query cost must not degrade linearly with feed size");
    }
}
