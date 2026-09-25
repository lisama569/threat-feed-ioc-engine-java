package com.github.lisama569.threatfeediocenginejava.ioc;

import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchResult;
import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchService;
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
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Concurrent ingestion + matching. Each indicator value appears in exactly one
 * batch; conflicting sources for the same value are inside the same batch, so
 * once a batch is committed the expected winner is fixed. Readers must observe:
 *  - before commit: miss; after commit: hit with the expected winner
 *  - never an intermediate/partial state, never a missed detection after commit.
 */
class ConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrencyTest.class);
    private static final int BATCHES = 40;
    private static final int VALUES_PER_BATCH = 50;

    @Test
    void concurrentIngestAndMatchIsConsistent() throws Exception {
        FeedParser parser = new FeedParser();
        IndicatorStore store = new IndicatorStore(List.of("feedA", "feedB", "feedC"));
        MatchService matcher = new MatchService(store, Clock.fixed(
                Instant.parse("2026-09-26T00:00:00Z"), ZoneOffset.UTC));

        // value -> (batchId, expected winning source) once that batch is committed
        record Expectation(String batchId, String value, String expectedSource) {
        }
        List<Expectation> expectations = new ArrayList<>();
        Map<String, List<String>> batchPayloads = new ConcurrentHashMap<>();
        for (int b = 0; b < BATCHES; b++) {
            String batchId = "batch-" + b;
            List<String> records = new ArrayList<>();
            for (int v = 0; v < VALUES_PER_BATCH; v++) {
                String value = "10." + b + "." + (v / 256) + "." + (v % 256);
                // two conflicting sources inside the SAME batch: feedA must win
                records.add("{\"type\":\"ip\",\"value\":\"" + value
                        + "\",\"source\":\"feedC\",\"confidence\":99}");
                records.add("{\"type\":\"ip\",\"value\":\"" + value
                        + "\",\"source\":\"feedA\",\"confidence\":10}");
                expectations.add(new Expectation(batchId, value, "feedA"));
            }
            batchPayloads.put(batchId, records);
        }

        Set<String> committed = ConcurrentHashMap.newKeySet();
        AtomicInteger violations = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(6);

        // writer thread: ingest batches one by one
        Future<?> writer = pool.submit(() -> {
            await(start);
            for (int b = 0; b < BATCHES; b++) {
                String batchId = "batch-" + b;
                String raw = "[" + String.join(",", batchPayloads.get(batchId)) + "]";
                store.ingest(batchId, parser.parse(raw, batchId));
                committed.add(batchId); // visible only AFTER the atomic merge
            }
        });

        // reader threads: continuously match random values
        List<Future<?>> readers = new ArrayList<>();
        for (int r = 0; r < 5; r++) {
            readers.add(pool.submit(() -> {
                await(start);
                ThreadLocalRandom rnd = ThreadLocalRandom.current();
                while (committed.size() < BATCHES) {
                    Expectation e = expectations.get(rnd.nextInt(expectations.size()));
                    boolean wasCommitted = committed.contains(e.batchId());
                    MatchResult result = matcher.match(IndicatorType.IP, e.value());
                    if (wasCommitted) {
                        if (!result.matched()) {
                            violations.incrementAndGet();
                            log.error("MISS after commit: {}", e);
                        } else if (!e.expectedSource().equals(result.indicator().source())) {
                            violations.incrementAndGet();
                            log.error("WRONG winner: expected={} got={}", e, result);
                        }
                    } else if (result.matched()
                            && !e.expectedSource().equals(result.indicator().source())) {
                        // partial state: some but not all records of a batch visible
                        violations.incrementAndGet();
                        log.error("INTERMEDIATE state: {} -> {}", e, result);
                    }
                }
            }));
        }

        start.countDown();
        writer.get(60, TimeUnit.SECONDS);
        for (Future<?> f : readers) {
            f.get(60, TimeUnit.SECONDS);
        }
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        // after everything is committed, every value must hit the deterministic winner
        int hits = 0;
        for (Expectation e : expectations) {
            MatchResult result = matcher.match(IndicatorType.IP, e.value());
            assertTrue(result.matched(), "must hit after full ingestion: " + e);
            assertEquals(e.expectedSource(), result.indicator().source());
            assertTrue(result.explanation().contains("source=feedA"),
                    "explanation must carry the判定依据");
            hits++;
        }
        log.info("concurrent run done: {} values verified, violations={}", hits, violations.get());
        assertEquals(0, violations.get(), "no missed/duplicate/intermediate reads allowed");
        assertEquals(BATCHES * VALUES_PER_BATCH, store.size());
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }
}
