package com.github.lisama569.iocengine;

import com.github.lisama569.iocengine.model.IngestResult;
import com.github.lisama569.iocengine.model.MatchVerdict;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.TestPropertySource;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end: ingest the bundled sample feeds (two sources, two formats),
 * then match the bundled sample events and verify the explained verdicts.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = "ioc.source-priority=internal:100,partner:50")
class EndToEndIT {

    private static final Logger LOG = Logger.getLogger(EndToEndIT.class.getName());

    @Autowired
    private TestRestTemplate rest;

    private String load(String path) throws Exception {
        try (var in = new ClassPathResource(path).getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void sampleFeedsAndEventsProduceDeterministicVerdicts() throws Exception {
        // ingest both sources; same batch re-imported must be a no-op
        IngestResult r1 = rest.postForObject("/api/feeds/json?batchId=internal-2026-09",
                load("sample-data/feed-internal.json"), IngestResult.class);
        IngestResult r2 = rest.postForObject("/api/feeds/csv?batchId=partner-2026-09",
                load("sample-data/feed-partner.csv"), IngestResult.class);
        IngestResult r2again = rest.postForObject("/api/feeds/csv?batchId=partner-2026-09",
                load("sample-data/feed-partner.csv"), IngestResult.class);
        LOG.info("internal accepted=" + r1.accepted() + " partner accepted=" + r2.accepted()
                + " partner re-import accepted=" + r2again.accepted());
        assertEquals(4, r1.accepted());
        assertEquals(5, r2.accepted());
        assertEquals(0, r2again.accepted()); // duplicate batch: no duplicate state/counts
        assertTrue(r2again.duplicateBatch());

        // match every sample event; log input + verdict basis
        for (String event : load("sample-data/events.txt").split("\\R")) {
            List<MatchVerdict> verdicts = List.of(
                    rest.postForObject("/api/events/match", event, MatchVerdict[].class));
            verdicts.forEach(v -> LOG.info("event=" + event + " -> " + v));
            if (event.contains("203.0.113.10")) {
                // conflict: internal (prio 100, conf 90, live) vs partner (prio 50, expired)
                MatchVerdict v = hitFor(verdicts, "203.0.113.10");
                assertEquals("internal", v.source());
                assertEquals(90, v.confidence());
                assertTrue(v.explanation().contains("internal"));
            }
            if (event.contains("8.8.8.8")) {
                assertTrue(verdicts.stream().noneMatch(MatchVerdict::hit),
                        "benign event must not hit");
            }
        }

        // expired indicator (partner 198.51.100.77, expired 2025-12-31) must not hit
        List<MatchVerdict> expired = List.of(rest.postForObject("/api/events/match",
                "fw dst=198.51.100.77", MatchVerdict[].class));
        expired.forEach(v -> LOG.info("expired-check -> " + v));
        assertTrue(expired.stream().noneMatch(MatchVerdict::hit));
    }

    @Test
    void malformedEntriesAreRejectedWithDistinctReasonsAndRawContent() {
        String payload = """
                {"type":"ipv4","value":"203.0.113.20","source":"internal"}
                {"type":"ipv4","value":"999.9.9.9","source":"internal"}
                {"type":"domain","value":"ok.example.com","source":"internal","expires_at":"garbage"}
                totally-broken
                """;
        IngestResult result = rest.postForObject("/api/feeds/json?batchId=bad-batch-1",
                payload, IngestResult.class);
        LOG.info("accepted=" + result.accepted() + " rejections=" + result.rejections());
        assertEquals(1, result.accepted());
        assertEquals(3, result.rejections().size());
        var reasons = result.rejections().stream().map(r -> r.reason().name()).toList();
        assertTrue(reasons.contains("INVALID_VALUE"));
        assertTrue(reasons.contains("INVALID_TIMESTAMP"));
        assertTrue(reasons.contains("MALFORMED_FORMAT"));
        // raw content of every rejected entry is retrievable
        assertTrue(result.rejections().stream().allMatch(r -> r.rawContent() != null && !r.rawContent().isBlank()));
        assertTrue(result.rejections().stream().anyMatch(r -> r.rawContent().contains("999.9.9.9")));
    }

    private static MatchVerdict hitFor(List<MatchVerdict> verdicts, String value) {
        return verdicts.stream()
                .filter(v -> v.value().equals(value) && v.hit())
                .findFirst()
                .orElseThrow(() -> new AssertionError("no hit for " + value + " in " + verdicts));
    }
}
