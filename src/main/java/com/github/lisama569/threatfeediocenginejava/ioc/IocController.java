package com.github.lisama569.threatfeediocenginejava.ioc;

import com.github.lisama569.threatfeediocenginejava.ioc.detect.EventDetectionService;
import com.github.lisama569.threatfeediocenginejava.ioc.detect.EventVerdict;
import com.github.lisama569.threatfeediocenginejava.ioc.fp.FalsePositiveRecord;
import com.github.lisama569.threatfeediocenginejava.ioc.fp.FalsePositiveRegistry;
import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchResult;
import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchService;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IngestionResult;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.FeedParser;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.ParsedFeed;
import com.github.lisama569.threatfeediocenginejava.ioc.store.IndicatorStore;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Local-only HTTP entry points for the ingest & detect flow. */
@RestController
@RequestMapping("/ioc")
public class IocController {

    private final FeedParser parser;
    private final IndicatorStore store;
    private final MatchService matcher;
    private final EventDetectionService detector;
    private final FalsePositiveRegistry falsePositives;

    public IocController(FeedParser parser, IndicatorStore store, MatchService matcher,
                         EventDetectionService detector, FalsePositiveRegistry falsePositives) {
        this.parser = parser;
        this.store = store;
        this.matcher = matcher;
        this.detector = detector;
        this.falsePositives = falsePositives;
    }

    /** Ingest a raw feed payload (JSON array or CSV). Batch id makes re-import idempotent. */
    @PostMapping("/ingest")
    public IngestionResult ingest(@RequestBody String rawFeed,
                                  @RequestHeader("X-Batch-Id") String batchId) {
        ParsedFeed parsed = parser.parse(rawFeed, batchId);
        return store.ingest(batchId, parsed);
    }

    /** Match one event field; explanation always included. */
    @GetMapping("/match")
    public MatchResult match(@RequestParam String type, @RequestParam String value) {
        IndicatorType t = IndicatorType.fromToken(type);
        if (t == null) {
            return MatchResult.miss("unsupported type: " + type);
        }
        return matcher.match(t, value.trim().toLowerCase());
    }

    /** Detect IOCs directly from one raw event text (request body). */
    @PostMapping("/detect")
    public EventVerdict detect(@RequestBody String eventText) {
        return detector.detect(eventText);
    }

    /** Detect a batch of raw event texts (JSON array of strings); one verdict each, in order. */
    @PostMapping("/detect/batch")
    public List<EventVerdict> detectBatch(@RequestBody List<String> eventTexts) {
        return detector.detectBatch(eventTexts);
    }

    /**
     * Mark an indicator as a false positive. Body JSON:
     * {"type":"domain","value":"evil.example.com","reason":"...","validUntil":"2027-01-01T00:00:00Z"}
     */
    @PostMapping("/false-positive")
    public FalsePositiveRecord markFalsePositive(@RequestBody Map<String, String> body) {
        IndicatorType type = IndicatorType.fromToken(body.get("type"));
        if (type == null) {
            throw new IllegalArgumentException("unsupported type: " + body.get("type"));
        }
        String value = body.get("value");
        String reason = body.get("reason");
        if (value == null || value.isBlank() || reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("value and reason are required");
        }
        Instant validUntil = Instant.parse(body.get("validUntil"));
        return falsePositives.mark(type, value, reason, validUntil);
    }

    /** Revoke a false-positive disposition; returns {"revoked": true/false}. */
    @DeleteMapping("/false-positive")
    public Map<String, Boolean> revokeFalsePositive(@RequestParam String type,
                                                    @RequestParam String value) {
        IndicatorType t = IndicatorType.fromToken(type);
        boolean revoked = t != null && falsePositives.revoke(t, value);
        return Map.of("revoked", revoked);
    }
}
