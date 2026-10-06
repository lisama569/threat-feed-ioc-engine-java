package com.github.lisama569.threatfeediocenginejava.ioc;

import com.github.lisama569.threatfeediocenginejava.ioc.detect.EventDetectionService;
import com.github.lisama569.threatfeediocenginejava.ioc.detect.EventVerdict;
import com.github.lisama569.threatfeediocenginejava.ioc.detect.IndicatorVerdict;
import com.github.lisama569.threatfeediocenginejava.ioc.extract.IocExtractor;
import com.github.lisama569.threatfeediocenginejava.ioc.fp.FalsePositiveRegistry;
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
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务点：事件原文检测 —— 多指标、重复指标、无指标、多来源叠加过期、批量、可复现。 */
class EventDetectionTest {

    private static final Logger log = LoggerFactory.getLogger(EventDetectionTest.class);
    private static final Instant NOW = Instant.parse("2026-10-01T00:00:00Z");

    private final FeedParser parser = new FeedParser();
    private final IndicatorStore store = new IndicatorStore(List.of("cert-feed", "community-feed"));
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final EventDetectionService detector = new EventDetectionService(
            new IocExtractor(), new MatchService(store, clock),
            new FalsePositiveRegistry(clock), clock);

    private void ingest(String batchId, String json) {
        store.ingest(batchId, parser.parse(json, batchId));
    }

    @Test
    void eventWithMultipleIndicatorsGetsPerIndicatorVerdictsAndOverall() {
        ingest("b1", """
                [
                  {"type":"ip","value":"203.0.113.7","source":"cert-feed","confidence":90,
                   "validUntil":"2027-01-01T00:00:00Z"},
                  {"type":"domain","value":"evil.example.com","source":"community-feed","confidence":70,
                   "validUntil":"2027-01-01T00:00:00Z"}
                ]
                """);
        EventVerdict v = detector.detect(
                "connection from 203.0.113.7 to evil.example.com and benign 192.0.2.1");
        v.indicators().forEach(i -> log.info("verdict: {}={} -> {} | {}",
                i.type(), i.value(), i.status(), i.explanation()));
        log.info("overall: {}", v.summary());

        assertEquals(EventVerdict.Verdict.HIT, v.verdict());
        assertEquals(3, v.indicators().size(), "three distinct indicators judged");
        assertEquals(IndicatorVerdict.Status.HIT, statusOf(v, IndicatorType.IP, "203.0.113.7"));
        assertEquals(IndicatorVerdict.Status.HIT, statusOf(v, IndicatorType.DOMAIN, "evil.example.com"));
        assertEquals(IndicatorVerdict.Status.MISS, statusOf(v, IndicatorType.IP, "192.0.2.1"));
        // 命中判定依据包含来源/置信度/有效期
        IndicatorVerdict hit = v.indicators().stream()
                .filter(i -> i.status() == IndicatorVerdict.Status.HIT).findFirst().orElseThrow();
        assertTrue(hit.explanation().contains("source=cert-feed"));
        assertTrue(hit.explanation().contains("confidence=90"));
        assertTrue(hit.explanation().contains("validUntil=2027-01-01T00:00:00Z"));
        assertEquals("cert-feed", hit.indicator().source());
    }

    @Test
    void repeatedIndicatorInOneEventIsJudgedOnce() {
        ingest("b2", """
                [{"type":"ip","value":"198.51.100.23","source":"cert-feed","confidence":80,
                  "validUntil":"2027-01-01T00:00:00Z"}]
                """);
        EventVerdict v = detector.detect("198.51.100.23 then 198.51.100.23 and again 198.51.100.23");
        log.info("repeated indicator -> {} verdict(s): {}", v.indicators().size(), v.summary());
        assertEquals(1, v.indicators().size(), "no duplicate judgement for repeated indicator");
        assertEquals(EventVerdict.Verdict.HIT, v.verdict());
    }

    @Test
    void eventWithoutAnyIndicatorYieldsExplicitNoIndicators() {
        EventVerdict v = detector.detect("a perfectly ordinary sentence with nothing to detect");
        log.info("no-ioc event -> {} | {}", v.verdict(), v.summary());
        assertEquals(EventVerdict.Verdict.NO_INDICATORS, v.verdict(),
                "must be an explicit conclusion, not an empty result or an error");
        assertTrue(v.indicators().isEmpty());
    }

    @Test
    void multiSourceWithPartiallyExpiredIntelFallsOnLiveRecord() {
        // 同一指标两个来源：高优先级的已过期，低优先级的仍生效 -> 结论落在生效的那条
        ingest("b3a", """
                [{"type":"domain","value":"stale.example.com","source":"cert-feed","confidence":95,
                  "validUntil":"2026-06-01T00:00:00Z"}]
                """);
        ingest("b3b", """
                [{"type":"domain","value":"stale.example.com","source":"community-feed","confidence":60,
                  "validUntil":"2027-06-01T00:00:00Z"}]
                """);
        EventVerdict v = detector.detect("dns query for stale.example.com detected");
        v.indicators().forEach(i -> log.info("partial-expiry verdict: {}", i.explanation()));
        assertEquals(EventVerdict.Verdict.HIT, v.verdict(),
                "expired high-priority record must not shadow the live one");
        IndicatorVerdict d = v.indicators().get(0);
        assertEquals("community-feed", d.indicator().source());
        assertEquals(60, d.indicator().confidence());

        // 两个来源都过期 -> 不命中
        ingest("b3c", """
                [{"type":"domain","value":"dead.example.com","source":"cert-feed","confidence":95,
                  "validUntil":"2026-01-01T00:00:00Z"}]
                """);
        ingest("b3d", """
                [{"type":"domain","value":"dead.example.com","source":"community-feed","confidence":60,
                  "validUntil":"2026-02-01T00:00:00Z"}]
                """);
        EventVerdict v2 = detector.detect("dns query for dead.example.com detected");
        log.info("all-expired verdict: {}", v2.summary());
        assertEquals(EventVerdict.Verdict.NO_HIT, v2.verdict(),
                "expired intel must never be hit");
    }

    @Test
    void batchDetectionReturnsOneVerdictPerEventInOrder() {
        ingest("b4", """
                [{"type":"email","value":"attacker@bad.example.org","source":"cert-feed",
                  "confidence":85,"validUntil":"2027-01-01T00:00:00Z"}]
                """);
        List<EventVerdict> results = detector.detectBatch(List.of(
                "mail from attacker@bad.example.org",
                "nothing suspicious here",
                "visit to unknown.example.net"));
        results.forEach(r -> log.info("batch item -> {} | {}", r.verdict(), r.summary()));
        assertEquals(3, results.size());
        assertEquals(EventVerdict.Verdict.HIT, results.get(0).verdict());
        assertEquals(EventVerdict.Verdict.NO_INDICATORS, results.get(1).verdict());
        assertEquals(EventVerdict.Verdict.NO_HIT, results.get(2).verdict());
    }

    @Test
    void sameEventDetectedTwiceYieldsIdenticalVerdict() {
        ingest("b5", """
                [{"type":"sha256","value":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                  "source":"cert-feed","confidence":100,"validUntil":"2027-01-01T00:00:00Z"}]
                """);
        String event = "file hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 seen";
        EventVerdict first = detector.detect(event);
        EventVerdict second = detector.detect(event);
        log.info("run1={} | run2={}", first.summary(), second.summary());
        assertEquals(first, second, "detection must be reproducible");
    }

    private static IndicatorVerdict.Status statusOf(EventVerdict v, IndicatorType type, String value) {
        return v.indicators().stream()
                .filter(i -> i.type() == type && i.value().equals(value))
                .map(IndicatorVerdict::status).findFirst().orElseThrow();
    }
}
