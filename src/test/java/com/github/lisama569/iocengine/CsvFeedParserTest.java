package com.github.lisama569.iocengine;

import com.github.lisama569.iocengine.ingest.CsvFeedParser;
import com.github.lisama569.iocengine.ingest.ParseOutcome;
import com.github.lisama569.iocengine.model.RejectedEntry;
import com.github.lisama569.iocengine.model.RejectionReason;
import org.junit.jupiter.api.Test;

import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class CsvFeedParserTest {

    private static final Logger LOG = Logger.getLogger(CsvFeedParserTest.class.getName());
    private final CsvFeedParser parser = new CsvFeedParser();

    @Test
    void acceptsValidRows() {
        String payload = """
                type,value,source,confidence,expires_at
                ipv4,203.0.113.10,partner,60,2027-01-01T00:00:00Z
                md5,44D88612FEA8A8F36DE82E1278ABB02F,partner,75,
                """;
        ParseOutcome outcome = parser.parse("c1", payload);
        LOG.info("records=" + outcome.records());
        assertEquals(2, outcome.records().size());
        assertTrue(outcome.rejections().isEmpty());
        // hash normalized to lowercase
        assertEquals("44d88612fea8a8f36de82e1278abb02f", outcome.records().get(1).value());
    }

    @Test
    void rejectsHeaderMissingRequiredColumns() {
        String payload = "type,value\nipv4,203.0.113.10\n";
        ParseOutcome outcome = parser.parse("c2", payload);
        RejectedEntry r = outcome.rejections().get(0);
        LOG.info("rejected reason=" + r.reason() + " detail=" + r.detail());
        assertEquals(RejectionReason.MISSING_FIELD, r.reason());
        assertTrue(r.rawContent().contains("type,value"));
    }

    @Test
    void rejectsShortRowAsMalformed() {
        String payload = """
                type,value,source,confidence
                ipv4,203.0.113.10
                """;
        ParseOutcome outcome = parser.parse("c3", payload);
        RejectedEntry r = outcome.rejections().get(0);
        LOG.info("rejected reason=" + r.reason() + " detail=" + r.detail());
        assertEquals(RejectionReason.MALFORMED_FORMAT, r.reason());
        assertEquals("ipv4,203.0.113.10", r.rawContent());
    }

    @Test
    void rejectsBadConfidenceAndBadTimestampDistinctly() {
        String payload = """
                type,value,source,confidence,expires_at
                domain,a.example.com,partner,abc,
                domain,b.example.com,partner,50,not-a-date
                """;
        ParseOutcome outcome = parser.parse("c4", payload);
        assertEquals(2, outcome.rejections().size());
        LOG.info("rejections=" + outcome.rejections());
        assertEquals(RejectionReason.INVALID_CONFIDENCE, outcome.rejections().get(0).reason());
        assertEquals(RejectionReason.INVALID_TIMESTAMP, outcome.rejections().get(1).reason());
    }
}
