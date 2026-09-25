package com.github.lisama569.iocengine;

import com.github.lisama569.iocengine.model.IocRecord;
import com.github.lisama569.iocengine.model.IocType;
import com.github.lisama569.iocengine.model.MatchVerdict;
import com.github.lisama569.iocengine.match.IocMatcher;
import com.github.lisama569.iocengine.store.IocStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class IocMatcherTest {

    private static final Logger LOG = Logger.getLogger(IocMatcherTest.class.getName());
    private static final Instant NOW = Instant.parse("2026-09-26T00:00:00Z");

    private IocStore store;
    private IocMatcher matcher;

    @BeforeEach
    void setUp() {
        store = new IocStore(Map.of("internal", 100, "partner", 50));
        matcher = new IocMatcher(store, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private void feed(String source, IocType type, String value, int conf, String expiresAt) {
        store.merge("batch-" + source + "-" + value, List.of(new IocRecord(
                type, value, source, conf, Instant.parse("2026-01-01T00:00:00Z"),
                expiresAt == null ? null : Instant.parse(expiresAt), "batch-" + source + "-" + value)));
    }

    @Test
    void hitCarriesExplanationWithSourceConfidenceAndExpiry() {
        feed("internal", IocType.IPV4, "203.0.113.10", 90, "2027-01-01T00:00:00Z");
        String event = "fw-denied src=10.1.1.5 dst=203.0.113.10 dport=4444";
        List<MatchVerdict> verdicts = matcher.match(event);
        verdicts.forEach(v -> LOG.info("event=" + event + " -> verdict=" + v));
        MatchVerdict hit = verdicts.stream().filter(MatchVerdict::hit).findFirst().orElseThrow();
        assertEquals(IocType.IPV4, hit.type());
        assertEquals("internal", hit.source());
        assertEquals(90, hit.confidence());
        assertEquals(Instant.parse("2027-01-01T00:00:00Z"), hit.expiresAt());
        assertTrue(hit.explanation().contains("internal"));
        assertTrue(hit.explanation().contains("90"));
    }

    @Test
    void expiredIndicatorDoesNotHit() {
        feed("internal", IocType.IPV4, "198.51.100.77", 100, "2025-12-31T00:00:00Z");
        String event = "fw dst=198.51.100.77";
        List<MatchVerdict> verdicts = matcher.match(event);
        verdicts.forEach(v -> LOG.info("event=" + event + " -> verdict=" + v));
        assertTrue(verdicts.stream().noneMatch(MatchVerdict::hit));
        assertTrue(verdicts.get(0).explanation().contains("no live"));
    }

    @Test
    void duplicateIndicatorInEventYieldsSingleVerdict() {
        feed("internal", IocType.DOMAIN, "evil-c2.example.com", 95, null);
        String event = "dns evil-c2.example.com retry evil-c2.example.com again EVIL-C2.EXAMPLE.COM";
        List<MatchVerdict> verdicts = matcher.match(event);
        verdicts.forEach(v -> LOG.info("verdict=" + v));
        long domainVerdicts = verdicts.stream().filter(v -> v.type() == IocType.DOMAIN).count();
        assertEquals(1, domainVerdicts);
        assertTrue(verdicts.get(0).hit());
    }

    @Test
    void urlAndEmailAndDomainExtractedWithoutOverlap() {
        feed("internal", IocType.URL, "http://evil-c2.example.com/beacon", 85, null);
        feed("partner", IocType.EMAIL, "phish@evil-c2.example.com", 80, null);
        String event = "proxy url=http://evil-c2.example.com/beacon mail from=phish@evil-c2.example.com";
        List<MatchVerdict> verdicts = matcher.match(event);
        verdicts.forEach(v -> LOG.info("verdict=" + v));
        assertTrue(verdicts.stream().anyMatch(v -> v.type() == IocType.URL && v.hit()));
        assertTrue(verdicts.stream().anyMatch(v -> v.type() == IocType.EMAIL && v.hit()));
        // domain inside URL/email spans must not be double-reported as a bare DOMAIN
        assertTrue(verdicts.stream().noneMatch(v -> v.type() == IocType.DOMAIN));
    }

    @Test
    void hashAndIpAndDomainAllMatchedInOneEvent() {
        feed("internal", IocType.SHA256,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 100, null);
        feed("internal", IocType.IPV4, "203.0.113.10", 90, null);
        String event = "edr sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
                + "then connected to 203.0.113.10 and visited benign.example.org";
        List<MatchVerdict> verdicts = matcher.match(event);
        verdicts.forEach(v -> LOG.info("verdict=" + v));
        assertEquals(2, verdicts.stream().filter(MatchVerdict::hit).count());
        assertTrue(verdicts.stream().anyMatch(v -> v.type() == IocType.DOMAIN && !v.hit()
                && v.value().equals("benign.example.org")));
    }
}
