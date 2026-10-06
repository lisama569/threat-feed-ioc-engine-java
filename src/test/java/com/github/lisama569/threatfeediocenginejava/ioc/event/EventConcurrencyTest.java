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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Business point: while ingestion, false-positive toggling and raw-event detection
 * run concurrently, a verdict is always one consistent state — HIT or
 * SUPPRESSED_HIT once intel is committed (never an intermediate MISS, never an
 * exception), and readers never observe a half-merged batch.
 */
class EventConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(EventConcurrencyTest.class);

    @Test
    void concurrentIngestSuppressAndDetectIsAlwaysConsistent() throws Exception {
        FeedParser parser = new FeedParser();
        IndicatorStore store = new IndicatorStore(List.of("feedA", "feedB"));
        Clock clock = Clock.fixed(Instant.parse("2026-10-01T00:00:00Z"), ZoneOffset.UTC);
        EventDetectionService detector =
                new EventDetectionService(new IocExtractor(), store, clock);
        FalsePositiveService fp = new FalsePositiveService(store, clock);
        Instant expires = Instant.parse("2026-12-31T00:00:00Z");

        // Preload the single indicator used by readers so it is live throughout.
        String target = "198.51.100.9";
        store.ingest("seed", parser.parse(
                "[{\"type\":\"ip\",\"value\":\"" + target + "\",\"source\":\"feedA\","
                        + "\"validUntil\":\"2027-01-01T00:00:00Z\"}]", "seed"));

        int otherBatches = 30;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        AtomicInteger violations = new AtomicInteger();
        AtomicInteger suppressionsSeen = new AtomicInteger();
        AtomicInteger hitsSeen = new AtomicInteger();
        List<Throwable> errors = new java.util.concurrent.CopyOnWriteArrayList<>();

        // writer 1: ingest unrelated batches continuously (lock churn)
        Future<?> ingester = pool.submit(() -> {
            await(start);
            try {
                for (int b = 0; b < otherBatches; b++) {
                    String batch = "batch-" + b;
                    String raw = "["
                            + "{\"type\":\"domain\",\"value\":\"d" + b + ".example.com\","
                            + "\"source\":\"feedB\",\"validUntil\":\"2027-01-01T00:00:00Z\"},"
                            + "{\"type\":\"ip\",\"value\":\"10.20." + b + ".1\","
                            + "\"source\":\"feedA\",\"validUntil\":\"2027-01-01T00:00:00Z\"}"
                            + "]";
                    store.ingest(batch, parser.parse(raw, batch));
                }
            } catch (Throwable t) {
                errors.add(t);
            }
        });

        // writer 2: repeatedly suppress then revoke the target
        Future<?> toggler = pool.submit(() -> {
            await(start);
            try {
                for (int i = 0; i < 200; i++) {
                    fp.suppress(IndicatorType.IP, target, "fp-" + i, expires);
                    fp.revoke(IndicatorType.IP, target);
                }
            } catch (Throwable t) {
                errors.add(t);
            }
        });

        // readers: detect raw events referencing the target
        List<Future<?>> readers = new java.util.ArrayList<>();
        for (int r = 0; r < 5; r++) {
            readers.add(pool.submit(() -> {
                await(start);
                try {
                    for (int i = 0; i < 1000; i++) {
                        String text = "event " + i + ": beacon " + target + " -> " + target;
                        EventDetectionResult result = detector.detect(text);
                        if (result.verdicts().size() != 1) {
                            violations.incrementAndGet();
                            continue;
                        }
                        IndicatorVerdict v = result.verdicts().get(0);
                        switch (v.status()) {
                            case HIT -> hitsSeen.incrementAndGet();
                            case SUPPRESSED_HIT -> {
                                suppressionsSeen.incrementAndGet();
                                if (v.indicator() == null || v.suppression() == null) {
                                    violations.incrementAndGet();
                                }
                            }
                            // live intel exists the entire time -> MISS would be an intermediate state
                            case MISS -> {
                                violations.incrementAndGet();
                                log.error("intermediate MISS while intel live: {}", v.explanation());
                            }
                        }
                    }
                } catch (Throwable t) {
                    errors.add(t);
                }
            }));
        }

        start.countDown();
        ingester.get(60, TimeUnit.SECONDS);
        toggler.get(60, TimeUnit.SECONDS);
        for (Future<?> f : readers) {
            f.get(60, TimeUnit.SECONDS);
        }
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        log.info("concurrent detect: hits={} suppressedHits={} violations={} errors={}",
                hitsSeen.get(), suppressionsSeen.get(), violations.get(), errors.size());
        assertEquals(0, errors.size(), "no exceptions under concurrency: " + errors);
        assertEquals(0, violations.get(), "no intermediate/inconsistent verdicts");
        assertTrue(hitsSeen.get() > 0, "both states must be observed: plain hits");
        assertTrue(suppressionsSeen.get() > 0, "both states must be observed: suppressed hits");

        // after toggling ends with a revoke, target is a plain HIT again
        EventDetectionResult end = detector.detect("final " + target);
        assertEquals(IndicatorVerdict.Status.HIT, end.verdicts().get(0).status());
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
