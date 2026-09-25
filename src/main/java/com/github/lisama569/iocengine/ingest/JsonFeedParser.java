package com.github.lisama569.iocengine.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.iocengine.model.IocRecord;
import com.github.lisama569.iocengine.model.IocType;
import com.github.lisama569.iocengine.model.RejectedEntry;
import com.github.lisama569.iocengine.model.RejectionReason;
import com.github.lisama569.iocengine.normalize.IocValues;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Parses JSON-lines feeds: one indicator object per line, e.g.
 * {"type":"ipv4","value":"1.2.3.4","source":"feed-a","confidence":80,
 *  "first_seen":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z"}
 * Bad lines are rejected with their raw content preserved; parsing never throws.
 */
@Component
public class JsonFeedParser implements FeedParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public String format() {
        return "json";
    }

    @Override
    public ParseOutcome parse(String batchId, String rawPayload) {
        List<IocRecord> records = new ArrayList<>();
        List<RejectedEntry> rejections = new ArrayList<>();
        if (rawPayload == null || rawPayload.isBlank()) {
            return new ParseOutcome(records, rejections);
        }
        String[] lines = rawPayload.split("\\R");
        for (String line : lines) {
            if (line.isBlank()) {
                continue;
            }
            parseLine(batchId, line, records, rejections);
        }
        return new ParseOutcome(records, rejections);
    }

    private void parseLine(String batchId, String line,
                           List<IocRecord> records, List<RejectedEntry> rejections) {
        JsonNode node;
        try {
            node = MAPPER.readTree(line);
        } catch (Exception e) {
            rejections.add(new RejectedEntry(RejectionReason.MALFORMED_FORMAT,
                    "line is not valid JSON: " + e.getMessage(), line));
            return;
        }
        if (!node.isObject()) {
            rejections.add(new RejectedEntry(RejectionReason.MALFORMED_FORMAT,
                    "line is not a JSON object", line));
            return;
        }

        String typeRaw = text(node, "type");
        String valueRaw = text(node, "value");
        String source = text(node, "source");
        if (typeRaw == null || valueRaw == null || source == null) {
            rejections.add(new RejectedEntry(RejectionReason.MISSING_FIELD,
                    "required field(s) missing: need type, value, source", line));
            return;
        }

        Optional<IocType> type = IocValues.parseType(typeRaw);
        if (type.isEmpty()) {
            rejections.add(new RejectedEntry(RejectionReason.UNSUPPORTED_TYPE,
                    "unsupported type: '" + typeRaw + "'", line));
            return;
        }

        Optional<String> value = IocValues.normalize(type.get(), valueRaw);
        if (value.isEmpty()) {
            rejections.add(new RejectedEntry(RejectionReason.INVALID_VALUE,
                    "value '" + valueRaw + "' is not a valid " + type.get(), line));
            return;
        }

        int confidence = 50; // default when absent
        JsonNode confNode = node.get("confidence");
        if (confNode != null && !confNode.isNull()) {
            if (!confNode.isInt() || confNode.intValue() < 0 || confNode.intValue() > 100) {
                rejections.add(new RejectedEntry(RejectionReason.INVALID_CONFIDENCE,
                        "confidence must be an integer in [0,100], got: " + confNode, line));
                return;
            }
            confidence = confNode.intValue();
        }

        Instant firstSeen;
        try {
            firstSeen = parseInstant(text(node, "first_seen"), Instant.EPOCH);
        } catch (DateTimeParseException e) {
            rejections.add(new RejectedEntry(RejectionReason.INVALID_TIMESTAMP,
                    "first_seen is not a valid ISO-8601 timestamp", line));
            return;
        }
        Instant expiresAt;
        try {
            expiresAt = parseInstant(text(node, "expires_at"), null);
        } catch (DateTimeParseException e) {
            rejections.add(new RejectedEntry(RejectionReason.INVALID_TIMESTAMP,
                    "expires_at is not a valid ISO-8601 timestamp", line));
            return;
        }

        records.add(new IocRecord(type.get(), value.get(), source.trim(),
                confidence, firstSeen, expiresAt, batchId));
    }

    private static String text(JsonNode node, String field) {
        JsonNode n = node.get(field);
        if (n == null || n.isNull()) {
            return null;
        }
        String s = n.isTextual() ? n.textValue() : n.toString();
        return s == null || s.isBlank() ? null : s;
    }

    private static Instant parseInstant(String raw, Instant defaultValue) {
        if (raw == null) {
            return defaultValue;
        }
        return Instant.parse(raw.trim());
    }
}
