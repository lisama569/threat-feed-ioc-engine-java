package com.github.lisama569.threatfeediocenginejava.ioc;

import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchResult;
import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchService;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IngestionResult;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.FeedParser;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.ParsedFeed;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end local flow: multi-source feeds (JSON + CSV) -> normalize -> merge
 * -> match events, with conflicts, expiry and malformed records all at once.
 */
class EndToEndFlowTest {

    private static final Logger log = LoggerFactory.getLogger(EndToEndFlowTest.class);
    private static final Instant NOW = Instant.parse("2026-09-26T12:00:00Z");

    @Test
    void fullLocalFlowIsDeterministicAndExplainable() {
        FeedParser parser = new FeedParser();
        IndicatorStore store = new IndicatorStore(List.of("cert-feed", "community-feed"));
        MatchService matcher = new MatchService(store, Clock.fixed(NOW, ZoneOffset.UTC));

        // source 1 (higher priority), JSON
        String certFeed = """
                [
                  {"type":"domain","value":"evil.example.com","source":"cert-feed",
                   "confidence":60,"validUntil":"2027-01-01T00:00:00Z"},
                  {"type":"ip","value":"203.0.113.7","source":"cert-feed",
                   "confidence":90,"validUntil":"2026-06-01T00:00:00Z"}
                ]
                """;
        // source 2 (lower priority), CSV — includes a malformed record
        String communityFeed = "type,value,source,confidence,validUntil\n"
                + "domain,evil.example.com,community-feed,95,2027-06-01T00:00:00Z\n"
                + "ip,198.51.100.23,community-feed,70,2027-01-01T00:00:00Z\n"
                + "ip,not-an-ip,community-feed,70,2027-01-01T00:00:00Z\n";

        IngestionResult r1 = store.ingest("cert-2026-09", parser.parse(certFeed, "cert-2026-09"));
        ParsedFeed parsed2 = parser.parse(communityFeed, "community-2026-09");
        IngestionResult r2 = store.ingest("community-2026-09", parsed2);
        log.info("ingest cert-feed -> {}", r1);
        log.info("ingest community-feed -> {}", r2);
        parsed2.rejected().forEach(r -> log.info("rejected: reason={} detail={} raw={}",
                r.reason(), r.detail(), r.rawContent()));

        assertEquals(2, r1.accepted());
        assertEquals(2, r2.accepted());
        assertEquals(1, r2.totalRejected());

        // event 1: conflicting domain -> higher-priority source wins despite lower confidence
        MatchResult m1 = matcher.match(IndicatorType.DOMAIN, "evil.example.com");
        log.info("event domain=evil.example.com -> {}", m1.explanation());
        assertTrue(m1.matched());
        assertEquals("cert-feed", m1.indicator().source());
        assertEquals(60, m1.indicator().confidence());

        // event 2: expired cert-feed ip -> miss
        MatchResult m2 = matcher.match(IndicatorType.IP, "203.0.113.7");
        log.info("event ip=203.0.113.7 -> {}", m2.explanation());
        assertFalse(m2.matched(), "expired indicator must not hit");

        // event 3: live community ip -> hit
        MatchResult m3 = matcher.match(IndicatorType.IP, "198.51.100.23");
        log.info("event ip=198.51.100.23 -> {}", m3.explanation());
        assertTrue(m3.matched());
        assertEquals("community-feed", m3.indicator().source());

        // event 4: unknown -> miss
        MatchResult m4 = matcher.match(IndicatorType.IP, "192.0.2.1");
        log.info("event ip=192.0.2.1 -> {}", m4.explanation());
        assertFalse(m4.matched());

        // re-import of both batches: no state change, no double counting
        IngestionResult again1 = store.ingest("cert-2026-09", parser.parse(certFeed, "cert-2026-09"));
        IngestionResult again2 = store.ingest("community-2026-09", parser.parse(communityFeed, "community-2026-09"));
        log.info("re-import cert -> {} | community -> {}", again1, again2);
        assertEquals(0, again1.accepted());
        assertEquals(2, again1.duplicates());
        assertEquals(0, again2.accepted());
        assertEquals(2, again2.duplicates());
        assertEquals(3, store.size());

        // verdicts unchanged after re-import
        assertEquals("cert-feed",
                matcher.match(IndicatorType.DOMAIN, "evil.example.com").indicator().source());
        assertFalse(matcher.match(IndicatorType.IP, "203.0.113.7").matched());
    }
}
