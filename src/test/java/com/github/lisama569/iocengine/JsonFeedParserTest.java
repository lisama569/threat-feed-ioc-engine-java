package com.github.lisama569.iocengine;

import com.github.lisama569.iocengine.ingest.JsonFeedParser;
import com.github.lisama569.iocengine.ingest.ParseOutcome;
import com.github.lisama569.iocengine.model.RejectedEntry;
import com.github.lisama569.iocengine.model.RejectionReason;
import org.junit.jupiter.api.Test;

import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class JsonFeedParserTest {

    private static final Logger LOG = Logger.getLogger(JsonFeedParserTest.class.getName());
    private final JsonFeedParser parser = new JsonFeedParser();

    @Test
    void acceptsValidEntries() {
        String payload = """
                {"type":"ipv4","value":"203.0.113.10","source":"internal","confidence":90,"expires_at":"2027-01-01T00:00:00Z"}
                {"type":"DOMAIN","value":"Evil-C2.Example.COM.","source":"internal"}
                """;
        ParseOutcome outcome = parser.parse("b1", payload);
        LOG.info("input=" + payload.replace('\n', ' ') + " -> records=" + outcome.records());
        assertEquals(2, outcome.records().size());
        assertTrue(outcome.rejections().isEmpty());
        // normalization: domain lowercased, trailing dot stripped
        assertEquals("evil-c2.example.com", outcome.records().get(1).value());
        assertEquals(50, outcome.records().get(1).confidence()); // default confidence
    }

    @Test
    void rejectsMalformedJsonAndKeepsRawContent() {
        String badLine = "{\"type\":\"ipv4\",\"value\":\"203.0.113.10\",";
        ParseOutcome outcome = parser.parse("b2", badLine);
        assertEquals(1, outcome.rejections().size());
        RejectedEntry r = outcome.rejections().get(0);
        LOG.info("input=" + badLine + " -> rejected reason=" + r.reason() + " detail=" + r.detail());
        assertEquals(RejectionReason.MALFORMED_FORMAT, r.reason());
        assertEquals(badLine, r.rawContent()); // raw content retrievable
    }

    @Test
    void rejectsMissingField() {
        String line = "{\"type\":\"ipv4\",\"source\":\"internal\"}";
        ParseOutcome outcome = parser.parse("b3", line);
        RejectedEntry r = outcome.rejections().get(0);
        LOG.info("input=" + line + " -> rejected reason=" + r.reason());
        assertEquals(RejectionReason.MISSING_FIELD, r.reason());
        assertEquals(line, r.rawContent());
    }

    @Test
    void rejectsUnsupportedType() {
        String line = "{\"type\":\"ipv6\",\"value\":\"::1\",\"source\":\"internal\"}";
        ParseOutcome outcome = parser.parse("b4", line);
        RejectedEntry r = outcome.rejections().get(0);
        LOG.info("input=" + line + " -> rejected reason=" + r.reason());
        assertEquals(RejectionReason.UNSUPPORTED_TYPE, r.reason());
    }

    @Test
    void rejectsInvalidValue() {
        String line = "{\"type\":\"ipv4\",\"value\":\"999.1.2.3\",\"source\":\"internal\"}";
        ParseOutcome outcome = parser.parse("b5", line);
        RejectedEntry r = outcome.rejections().get(0);
        LOG.info("input=" + line + " -> rejected reason=" + r.reason());
        assertEquals(RejectionReason.INVALID_VALUE, r.reason());
    }

    @Test
    void rejectsInvalidTimestamp() {
        String line = "{\"type\":\"domain\",\"value\":\"bad.example.com\",\"source\":\"internal\",\"expires_at\":\"next-tuesday\"}";
        ParseOutcome outcome = parser.parse("b6", line);
        RejectedEntry r = outcome.rejections().get(0);
        LOG.info("input=" + line + " -> rejected reason=" + r.reason());
        assertEquals(RejectionReason.INVALID_TIMESTAMP, r.reason());
        assertEquals(line, r.rawContent());
    }

    @Test
    void rejectsInvalidConfidence() {
        String line = "{\"type\":\"domain\",\"value\":\"x.example.com\",\"source\":\"internal\",\"confidence\":150}";
        ParseOutcome outcome = parser.parse("b7", line);
        RejectedEntry r = outcome.rejections().get(0);
        LOG.info("input=" + line + " -> rejected reason=" + r.reason());
        assertEquals(RejectionReason.INVALID_CONFIDENCE, r.reason());
    }

    @Test
    void mixedPayloadKeepsGoodAndRejectsBad() {
        String payload = """
                {"type":"ipv4","value":"203.0.113.10","source":"internal"}
                not-json-at-all
                {"type":"ipv4","value":"203.0.113.11","source":"internal"}
                """;
        ParseOutcome outcome = parser.parse("b8", payload);
        LOG.info("accepted=" + outcome.records().size() + " rejected=" + outcome.rejections());
        assertEquals(2, outcome.records().size());
        assertEquals(1, outcome.rejections().size());
        assertEquals(RejectionReason.MALFORMED_FORMAT, outcome.rejections().get(0).reason());
    }
}
