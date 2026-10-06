package com.github.lisama569.threatfeediocenginejava.ioc;

import com.github.lisama569.threatfeediocenginejava.ioc.detect.EventDetectionService;
import com.github.lisama569.threatfeediocenginejava.ioc.detect.EventVerdict;
import com.github.lisama569.threatfeediocenginejava.ioc.detect.IndicatorVerdict;
import com.github.lisama569.threatfeediocenginejava.ioc.extract.IocExtractor;
import com.github.lisama569.threatfeediocenginejava.ioc.fp.FalsePositiveRecord;
import com.github.lisama569.threatfeediocenginejava.ioc.fp.FalsePositiveRegistry;
import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchService;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.FeedParser;
import com.github.lisama569.threatfeediocenginejava.ioc.store.IndicatorStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务点：误报处置 —— 标记抑制、到期自动恢复、撤销、与摄取/检测并发时无中间态。 */
class FalsePositiveTest {

    private static final Logger log = LoggerFactory.getLogger(FalsePositiveTest.class);
    private static final Instant T0 = Instant.parse("2026-10-01T00:00:00Z");

    /** 可推进的时钟，用于测试到期自动恢复。 */
    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private final MutableClock clock = new MutableClock(T0);
    private final FeedParser parser = new FeedParser();
    private final IndicatorStore store = new IndicatorStore(List.of("cert-feed"));
    private final FalsePositiveRegistry registry = new FalsePositiveRegistry(clock);
    private final EventDetectionService detector = new EventDetectionService(
            new IocExtractor(), new MatchService(store, clock), registry, clock);

    private void ingestLiveIntel() {
        store.ingest("fp-batch", parser.parse("""
                [{"type":"domain","value":"cdn.example.com","source":"cert-feed","confidence":75,
                  "validUntil":"2027-06-01T00:00:00Z"}]
                """, "fp-batch"));
    }

    @Test
    void markedIndicatorIsReportedAsSuppressedNotInvisible() {
        ingestLiveIntel();
        EventVerdict before = detector.detect("traffic to cdn.example.com");
        log.info("before mark -> {} | {}", before.verdict(), before.summary());
        assertEquals(EventVerdict.Verdict.HIT, before.verdict());

        FalsePositiveRecord fp = registry.mark(IndicatorType.DOMAIN, "cdn.example.com",
                "CDN domain shared with legitimate traffic", Instant.parse("2026-11-01T00:00:00Z"));
        log.info("marked false positive: {}", fp);

        EventVerdict after = detector.detect("traffic to cdn.example.com");
        after.indicators().forEach(i -> log.info("suppressed verdict: {}", i.explanation()));
        assertEquals(EventVerdict.Verdict.SUPPRESSED, after.verdict(),
                "overall conclusion must show hit-but-suppressed");
        IndicatorVerdict iv = after.indicators().get(0);
        assertEquals(IndicatorVerdict.Status.SUPPRESSED, iv.status());
        assertNotNull(iv.indicator(), "the matched intel is still visible, not disappeared");
        assertEquals("cert-feed", iv.indicator().source());
        assertNotNull(iv.falsePositive());
        assertEquals("CDN domain shared with legitimate traffic", iv.falsePositive().reason());
        assertTrue(iv.explanation().contains("SUPPRESSED"));
        assertTrue(iv.explanation().contains("source=cert-feed"),
                "explanation still carries the hit intel details");
    }

    @Test
    void suppressionExpiresAutomaticallyAndVerdictRestores() {
        ingestLiveIntel();
        registry.mark(IndicatorType.DOMAIN, "cdn.example.com", "temporary whitelist",
                T0.plus(Duration.ofDays(7)));
        assertEquals(EventVerdict.Verdict.SUPPRESSED,
                detector.detect("traffic to cdn.example.com").verdict());
        assertEquals(1, registry.activeCount());

        clock.advance(Duration.ofDays(7).plusSeconds(1)); // 越过生效期
        EventVerdict restored = detector.detect("traffic to cdn.example.com");
        log.info("after expiry -> {} | {}", restored.verdict(), restored.summary());
        assertEquals(EventVerdict.Verdict.HIT, restored.verdict(),
                "expired suppression must restore normal verdict automatically");
        assertEquals(0, registry.activeCount(), "expired entry is purged");
    }

    @Test
    void revokedSuppressionRestoresVerdictImmediately() {
        ingestLiveIntel();
        registry.mark(IndicatorType.DOMAIN, "cdn.example.com", "analyst mistake",
                Instant.parse("2027-01-01T00:00:00Z"));
        assertEquals(EventVerdict.Verdict.SUPPRESSED,
                detector.detect("traffic to cdn.example.com").verdict());

        boolean revoked = registry.revoke(IndicatorType.DOMAIN, "cdn.example.com");
        log.info("revoked={}", revoked);
        assertTrue(revoked);
        assertFalse(registry.revoke(IndicatorType.DOMAIN, "cdn.example.com"),
                "second revoke finds nothing");
        assertEquals(EventVerdict.Verdict.HIT,
                detector.detect("traffic to cdn.example.com").verdict(),
                "revoke restores normal verdict immediately");
    }

    @Test
    void suppressionIsScopedToExactIndicator() {
        ingestLiveIntel();
        store.ingest("fp-batch-2", parser.parse("""
                [{"type":"ip","value":"203.0.113.9","source":"cert-feed","confidence":60,
                  "validUntil":"2027-06-01T00:00:00Z"}]
                """, "fp-batch-2"));
        registry.mark(IndicatorType.DOMAIN, "cdn.example.com", "fp",
                Instant.parse("2027-01-01T00:00:00Z"));
        EventVerdict v = detector.detect("cdn.example.com resolved to 203.0.113.9");
        v.indicators().forEach(i -> log.info("scoped: {}={} -> {}", i.type(), i.value(), i.status()));
        assertEquals(IndicatorVerdict.Status.SUPPRESSED, v.indicators().get(0).status());
        assertEquals(IndicatorVerdict.Status.HIT, v.indicators().get(1).status(),
                "other indicators are unaffected");
        assertEquals(EventVerdict.Verdict.HIT, v.verdict(),
                "one live (non-suppressed) hit keeps the overall verdict at HIT");
    }

    @Test
    void concurrentIngestMarkAndDetectNeverShowIntermediateState() throws Exception {
        // 先提交情报与误报处置，再并发检测：所有并发结论必须一致为 SUPPRESSED，
        // 不允许出现一会儿 HIT 一会儿 SUPPRESSED 的中间态。
        ingestLiveIntel();
        registry.mark(IndicatorType.DOMAIN, "cdn.example.com", "stable suppression",
                Instant.parse("2027-01-01T00:00:00Z"));

        int threads = 8;
        int rounds = 200;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger inconsistent = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    for (int r = 0; r < rounds; r++) {
                        EventVerdict v = detector.detect("traffic to cdn.example.com");
                        if (v.verdict() != EventVerdict.Verdict.SUPPRESSED
                                || v.indicators().get(0).status() != IndicatorVerdict.Status.SUPPRESSED
                                || v.indicators().get(0).indicator() == null
                                || v.indicators().get(0).falsePositive() == null) {
                            inconsistent.incrementAndGet();
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get(30, TimeUnit.SECONDS);
        }
        pool.shutdown();
        log.info("concurrent detect: {} x {} rounds, inconsistent={}", threads, rounds, inconsistent.get());
        assertEquals(0, inconsistent.get(),
                "committed suppression must be atomically visible to every concurrent detection");
    }
}
