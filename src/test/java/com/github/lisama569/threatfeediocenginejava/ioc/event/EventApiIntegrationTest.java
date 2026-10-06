package com.github.lisama569.threatfeediocenginejava.ioc.event;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Full-stack (local, random port) coverage of the new endpoints:
 * ingest -> raw-event detect (single + batch) -> mark false positive -> suppressed
 * verdict -> revoke -> hit again. Also checks the no-indicator event body.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class EventApiIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(EventApiIntegrationTest.class);

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @BeforeEach
    void seed() {
        HttpHeaders h = new HttpHeaders();
        h.set("X-Batch-Id", "api-seed");
        h.setContentType(MediaType.APPLICATION_JSON);
        String body = """
                [
                  {"type":"ip","value":"203.0.113.50","source":"feedA","confidence":88,
                   "validUntil":"2027-01-01T00:00:00Z"},
                  {"type":"domain","value":"c2.example.com","source":"feedB","confidence":70,
                   "validUntil":"2027-01-01T00:00:00Z"}
                ]
                """;
        rest.exchange(url("/ioc/ingest"), HttpMethod.POST, new HttpEntity<>(body, h), String.class);
    }

    @Test
    void detectSuppressRevokeThroughHttp() {
        // 1) raw single event -> threat
        EventDetectionResult hit = rest.postForObject(url("/ioc/events/detect"),
                "callback 203.0.113.50 to c2.example.com", EventDetectionResult.class);
        log.info("detect -> {}", hit.conclusion());
        assertEquals(EventConclusion.THREAT_DETECTED, hit.conclusion());
        assertEquals(2, hit.extracted());

        // 2) event with no indicators -> explicit body, not empty/error
        EventDetectionResult none = rest.postForObject(url("/ioc/events/detect"),
                "just some prose without indicators", EventDetectionResult.class);
        log.info("detect-none -> {}", none.conclusion());
        assertEquals(EventConclusion.NO_DETECTABLE_INDICATORS, none.conclusion());

        // 3) batch
        BatchDetectionRequest req = new BatchDetectionRequest(List.of(
                new BatchDetectionRequest.EventItem("a", "203.0.113.50"),
                new BatchDetectionRequest.EventItem("b", "no indicators here")));
        EventDetectionResult[] batch = rest.postForObject(
                url("/ioc/events/detect-batch"), req, EventDetectionResult[].class);
        log.info("batch -> {} / {}", batch[0].conclusion(), batch[1].conclusion());
        assertEquals(2, batch.length);
        assertEquals(EventConclusion.THREAT_DETECTED, batch[0].conclusion());
        assertEquals(EventConclusion.NO_DETECTABLE_INDICATORS, batch[1].conclusion());

        // 4) mark ip as false positive
        Map<String, String> fpReq = Map.of(
                "type", "ip",
                "value", "203.0.113.50",
                "reason", "corporate proxy",
                "expiresAt", "2030-01-01T00:00:00Z");
        ResponseEntity<String> created = rest.postForEntity(
                url("/ioc/false-positives"), fpReq, String.class);
        assertTrue(created.getStatusCode().is2xxSuccessful());
        log.info("suppress created: {}", created.getBody());

        // 5) now a raw event mentioning only the suppressed ip -> ALL_HITS_SUPPRESSED
        EventDetectionResult suppressed = rest.postForObject(url("/ioc/events/detect"),
                "proxy 203.0.113.50 again", EventDetectionResult.class);
        log.info("detect after suppress -> {}", suppressed.conclusion());
        assertEquals(EventConclusion.ALL_HITS_SUPPRESSED, suppressed.conclusion());
        assertEquals("SUPPRESSED_HIT", suppressed.verdicts().get(0).status().name());
        assertTrue(suppressed.verdicts().get(0).explanation().contains("corporate proxy"));

        // 6) revoke -> hit again
        Boolean revoked = rest.exchange(
                url("/ioc/false-positives?type=ip&value=203.0.113.50"),
                HttpMethod.DELETE, HttpEntity.EMPTY, Boolean.class).getBody();
        log.info("revoke response -> {}", revoked);
        assertTrue(Boolean.TRUE.equals(revoked));
        EventDetectionResult afterRevoke = rest.postForObject(url("/ioc/events/detect"),
                "203.0.113.50", EventDetectionResult.class);
        assertEquals(EventConclusion.THREAT_DETECTED, afterRevoke.conclusion());
        assertEquals("HIT", afterRevoke.verdicts().get(0).status().name());
    }
}
