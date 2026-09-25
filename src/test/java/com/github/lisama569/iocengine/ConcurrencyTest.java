package com.github.lisama569.iocengine;

import com.github.lisama569.iocengine.ingest.IngestService;
import com.github.lisama569.iocengine.ingest.JsonFeedParser;
import com.github.lisama569.iocengine.match.IocMatcher;
import com.github.lisama569.iocengine.model.MatchVerdict;
import com.github.lisama569.iocengine.store.IocStore;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Concurrent ingestion + matching must never produce missed hits (after the
 * data is visible), duplicate hits, or verdicts built from intermediate state.
 */
class ConcurrencyTest {

    private static final Logger LOG = Logger.getLogger(ConcurrencyTest.class.getName());
    private static final Instant NOW = Instant.parse("2026-09-26T00:00:00Z");
    private static final int BATCHES = 50;
    private static final int PER_BATCH = 20;

    @Test
    void concurrentIngestAndQueryStayConsistent() throws Exception {
        IocStore store = new IocStore(Map.of("internal", 100));
        IngestService ingest = new IngestService(List.of(new JsonFeedParser()), store);
        IocMatcher matcher = new IocMatcher(store, Clock.fixed(NOW, ZoneOffset.UTC));

        ConcurrentLinkedQueue<String> violations = new ConcurrentLinkedQueue<>();
        AtomicBoolean stop = new AtomicBoolean(false);
        CountDownLatch readersDone = new CountDownLatch(3);
        ExecutorService pool = Executors.newFixedThreadPool(4);

        // readers: continuously match an event containing one known indicator
        for (int r = 0; r < 3; r++) {
            int idx = r;
            pool.submit(() -> {
                try {
                    while (!stop.get()) {
                        int i = (int) (Math.random() * BATCHES * PER_BATCH);
                        String ip = "10.0." + (i / 256) + "." + (i % 256);
                        List<MatchVerdict> verdicts = matcher.match("probe dst=" + ip);
                        // exactly one verdict per distinct indicator: no duplicates
                        if (verdicts.size() != 1) {
                            violations.add("duplicate/missing verdict for " + ip + ": " + verdicts);
                        }
                        for (MatchVerdict v : verdicts) {
                            if (v.hit()) {
                                // a hit must reflect fully-ingested data, never an intermediate state
                                if (!"internal".equals(v.source()) || v.confidence() != 77) {
                                    violations.add("intermediate-state verdict: " + v);
                                }
                            }
                        }
                    }
                } finally {
                    readersDone.countDown();
                    LOG.info("reader " + idx + " stopped");
                }
            });
        }

        // writer: ingest BATCHES batches, each with PER_BATCH distinct indicators
        var writer = pool.submit(() -> {
            for (int b = 0; b < BATCHES; b++) {
                StringBuilder payload = new StringBuilder();
                for (int j = 0; j < PER_BATCH; j++) {
                    int i = b * PER_BATCH + j;
                    payload.append("{\"type\":\"ipv4\",\"value\":\"10.0.")
                            .append(i / 256).append('.').append(i % 256)
                            .append("\",\"source\":\"internal\",\"confidence\":77,")
                            .append("\"expires_at\":\"2027-01-01T00:00:00Z\"}\n");
                }
                ingest.ingest("json", "batch-" + b, payload.toString());
            }
        });

        writer.get(60, TimeUnit.SECONDS); // wait only for the writer
        stop.set(true);
        assertTrue(readersDone.await(30, TimeUnit.SECONDS));
        pool.shutdownNow();

        LOG.info("violations=" + violations.size());
        assertTrue(violations.isEmpty(), () -> "consistency violations: " + violations);

        // after ingestion completes, every indicator must hit: no missed detections
        int misses = 0;
        for (int i = 0; i < BATCHES * PER_BATCH; i++) {
            String ip = "10.0." + (i / 256) + "." + (i % 256);
            List<MatchVerdict> v = matcher.match("probe dst=" + ip);
            if (v.stream().noneMatch(MatchVerdict::hit)) {
                misses++;
            }
        }
        LOG.info("post-ingest misses=" + misses + " store size=" + store.size());
        assertEquals(0, misses);
        assertEquals(BATCHES * PER_BATCH, store.size());

        // re-ingesting the same batches is a no-op: no duplicate state
        int before = store.size();
        ingest.ingest("json", "batch-0", "{\"type\":\"ipv4\",\"value\":\"10.0.0.0\",\"source\":\"internal\",\"confidence\":77}");
        assertEquals(before, store.size());
    }
}
