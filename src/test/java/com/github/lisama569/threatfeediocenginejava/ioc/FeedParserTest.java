package com.github.lisama569.threatfeediocenginejava.ioc;

import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.model.RejectedRecord;
import com.github.lisama569.threatfeediocenginejava.ioc.model.RejectionReason;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.FeedParser;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.ParsedFeed;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FeedParserTest {

    private static final Logger log = LoggerFactory.getLogger(FeedParserTest.class);
    private final FeedParser parser = new FeedParser();

    @Test
    void parsesValidJsonFeed() {
        String raw = """
                [
                  {"type":"ip","value":"1.2.3.4","source":"feedA","confidence":80,
                   "validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-01-01T00:00:00Z"},
                  {"type":"DOMAIN","value":"Evil.Example.COM","source":"feedB"}
                ]
                """;
        ParsedFeed feed = parser.parse(raw, "b1");
        log.info("input={} -> indicators={} rejected={}", raw, feed.indicators(), feed.rejected());
        assertEquals(2, feed.indicators().size());
        assertEquals(0, feed.rejected().size());
        // normalization: domain lower-cased
        assertEquals("evil.example.com", feed.indicators().get(1).value());
        assertEquals(IndicatorType.DOMAIN, feed.indicators().get(1).type());
        // default confidence
        assertEquals(50, feed.indicators().get(1).confidence());
    }

    @Test
    void parsesValidCsvFeed() {
        String raw = "type,value,source,confidence,validUntil\n"
                + "sha256," + "a".repeat(64) + ",feedC,90,2027-06-01T00:00:00Z\n";
        ParsedFeed feed = parser.parse(raw, "b2");
        log.info("input={} -> indicators={} rejected={}", raw, feed.indicators(), feed.rejected());
        assertEquals(1, feed.indicators().size());
        assertEquals(IndicatorType.HASH_SHA256, feed.indicators().get(0).type());
        assertEquals(90, feed.indicators().get(0).confidence());
    }

    @Test
    void rejectsMalformedJsonWithRawContent() {
        String raw = "[{\"type\":\"ip\",\"value\":";
        ParsedFeed feed = parser.parse(raw, "b3");
        log.info("input={} -> rejected={}", raw, feed.rejected());
        assertEquals(1, feed.rejected().size());
        RejectedRecord r = feed.rejected().get(0);
        assertEquals(RejectionReason.MALFORMED_FORMAT, r.reason());
        assertEquals(raw, r.rawContent(), "raw content must be retrievable");
    }

    @Test
    void rejectsRecordLevelProblemsWithDistinctReasons() {
        String raw = """
                [
                  {"value":"1.2.3.4","source":"feedA"},
                  {"type":"ip","source":"feedA"},
                  {"type":"ip","value":"1.2.3.4"},
                  {"type":"netblock","value":"10.0.0.0/8","source":"feedA"},
                  {"type":"ip","value":"999.1.2.3","source":"feedA"},
                  {"type":"ip","value":"1.2.3.4","source":"feedA","validUntil":"not-a-time"},
                  {"type":"ip","value":"1.2.3.4","source":"feedA","confidence":300}
                ]
                """;
        ParsedFeed feed = parser.parse(raw, "b4");
        feed.rejected().forEach(r -> log.info("rejected reason={} detail={} raw={}",
                r.reason(), r.detail(), r.rawContent()));
        assertEquals(7, feed.rejected().size());
        assertEquals(RejectionReason.MISSING_FIELD, feed.rejected().get(0).reason());   // no type
        assertEquals(RejectionReason.MISSING_FIELD, feed.rejected().get(1).reason());   // no value
        assertEquals(RejectionReason.MISSING_FIELD, feed.rejected().get(2).reason());   // no source
        assertEquals(RejectionReason.UNSUPPORTED_TYPE, feed.rejected().get(3).reason());
        assertEquals(RejectionReason.INVALID_VALUE, feed.rejected().get(4).reason());
        assertEquals(RejectionReason.INVALID_TIMESTAMP, feed.rejected().get(5).reason());
        assertEquals(RejectionReason.INVALID_CONFIDENCE, feed.rejected().get(6).reason());
        // every rejected record keeps its raw content
        feed.rejected().forEach(r -> {
            assertTrue(r.rawContent().startsWith("{") && r.rawContent().endsWith("}"),
                    "raw content of the rejected record must be retrievable");
            assertTrue(r.detail() != null && !r.detail().isBlank());
        });
    }

    @Test
    void csvMissingRequiredColumnIsRejected() {
        String raw = "type,value\nip,1.2.3.4\n";
        ParsedFeed feed = parser.parse(raw, "b5");
        log.info("input={} -> rejected={}", raw, feed.rejected());
        assertEquals(1, feed.rejected().size());
        assertEquals(RejectionReason.MISSING_FIELD, feed.rejected().get(0).reason());
    }

    @Test
    void mixedValidAndInvalidRecordsNothingSilentlyDropped() {
        String raw = """
                [
                  {"type":"ip","value":"8.8.8.8","source":"feedA"},
                  {"type":"ip","value":"bad-ip","source":"feedA"},
                  {"type":"md5","value":"d41d8cd98f00b204e9800998ecf8427e","source":"feedB"}
                ]
                """;
        ParsedFeed feed = parser.parse(raw, "b6");
        log.info("input={} -> indicators={} rejected={}", raw, feed.indicators(), feed.rejected());
        assertEquals(2, feed.indicators().size());
        assertEquals(1, feed.rejected().size());
        assertEquals(3, feed.indicators().size() + feed.rejected().size(),
                "every input record accounted for");
    }
}
