package com.github.lisama569.threatfeediocenginejava.ioc.parse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.threatfeediocenginejava.ioc.model.Indicator;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.model.RejectedRecord;
import com.github.lisama569.threatfeediocenginejava.ioc.model.RejectionReason;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Parses raw feed payloads (JSON or CSV) into normalized indicators.
 * Malformed records are never silently dropped: they are returned as
 * {@link RejectedRecord} with a classified reason and the original raw content.
 */
@Component
public class FeedParser {

    private static final Pattern IPV4 = Pattern.compile(
            "^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern DOMAIN = Pattern.compile(
            "^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$");
    private static final Pattern EMAIL = Pattern.compile(
            "^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,63}$");
    private static final Pattern MD5 = Pattern.compile("^[0-9a-f]{32}$");
    private static final Pattern SHA1 = Pattern.compile("^[0-9a-f]{40}$");
    private static final Pattern SHA256 = Pattern.compile("^[0-9a-f]{64}$");

    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Parse a raw feed payload. Format is auto-detected (JSON array/object vs CSV).
     * Every input record ends up either as a normalized {@link Indicator}
     * or as a {@link RejectedRecord} — nothing is silently discarded.
     */
    public ParsedFeed parse(String raw, String batchId) {
        List<Indicator> indicators = new ArrayList<>();
        List<RejectedRecord> rejected = new ArrayList<>();
        if (raw == null || raw.isBlank()) {
            rejected.add(new RejectedRecord(String.valueOf(raw),
                    RejectionReason.MALFORMED_FORMAT, "empty feed payload"));
            return new ParsedFeed(indicators, rejected);
        }
        FeedFormat format = FeedFormat.detect(raw);
        if (format == FeedFormat.JSON) {
            parseJson(raw, batchId, indicators, rejected);
        } else {
            parseCsv(raw, batchId, indicators, rejected);
        }
        return new ParsedFeed(indicators, rejected);
    }

    private void parseJson(String raw, String batchId,
                           List<Indicator> indicators, List<RejectedRecord> rejected) {
        JsonNode root;
        try {
            root = mapper.readTree(raw);
        } catch (Exception e) {
            rejected.add(new RejectedRecord(raw, RejectionReason.MALFORMED_FORMAT,
                    "invalid JSON: " + e.getMessage()));
            return;
        }
        if (!root.isArray()) {
            rejected.add(new RejectedRecord(raw, RejectionReason.MALFORMED_FORMAT,
                    "JSON feed must be an array of records"));
            return;
        }
        for (JsonNode node : root) {
            if (!node.isObject()) {
                rejected.add(new RejectedRecord(node.toString(), RejectionReason.MALFORMED_FORMAT,
                        "JSON record must be an object"));
                continue;
            }
            validateAndBuild(
                    text(node, "type"), text(node, "value"), text(node, "source"),
                    text(node, "confidence"), text(node, "validFrom"), text(node, "validUntil"),
                    node.toString(), batchId, indicators, rejected);
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v == null || v.isNull() ? null : v.asText();
    }

    private void parseCsv(String raw, String batchId,
                          List<Indicator> indicators, List<RejectedRecord> rejected) {
        String[] lines = raw.split("\\R");
        if (lines.length == 0) {
            rejected.add(new RejectedRecord(raw, RejectionReason.MALFORMED_FORMAT, "empty CSV feed"));
            return;
        }
        String[] header = lines[0].split(",", -1);
        List<String> cols = new ArrayList<>();
        for (String h : header) {
            cols.add(h.trim());
        }
        for (String required : List.of("type", "value", "source")) {
            if (!cols.contains(required)) {
                rejected.add(new RejectedRecord(lines[0], RejectionReason.MISSING_FIELD,
                        "CSV header missing required column: " + required));
                return;
            }
        }
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isBlank()) {
                continue; // blank lines carry no record; nothing to reject
            }
            String[] cells = line.split(",", -1);
            String type = cell(cols, cells, "type");
            String value = cell(cols, cells, "value");
            String source = cell(cols, cells, "source");
            String confidence = cell(cols, cells, "confidence");
            String validFrom = cell(cols, cells, "validFrom");
            String validUntil = cell(cols, cells, "validUntil");
            validateAndBuild(type, value, source, confidence, validFrom, validUntil,
                    line, batchId, indicators, rejected);
        }
    }

    private static String cell(List<String> cols, String[] cells, String name) {
        int idx = cols.indexOf(name);
        if (idx < 0 || idx >= cells.length) {
            return null;
        }
        String v = cells[idx].trim();
        return v.isEmpty() ? null : v;
    }

    private void validateAndBuild(String typeToken, String value, String source,
                                  String confidenceStr, String validFromStr, String validUntilStr,
                                  String rawRecord, String batchId,
                                  List<Indicator> indicators, List<RejectedRecord> rejected) {
        if (typeToken == null || typeToken.isBlank()) {
            rejected.add(new RejectedRecord(rawRecord, RejectionReason.MISSING_FIELD, "missing field: type"));
            return;
        }
        if (value == null || value.isBlank()) {
            rejected.add(new RejectedRecord(rawRecord, RejectionReason.MISSING_FIELD, "missing field: value"));
            return;
        }
        if (source == null || source.isBlank()) {
            rejected.add(new RejectedRecord(rawRecord, RejectionReason.MISSING_FIELD, "missing field: source"));
            return;
        }
        IndicatorType type = IndicatorType.fromToken(typeToken);
        if (type == null) {
            rejected.add(new RejectedRecord(rawRecord, RejectionReason.UNSUPPORTED_TYPE,
                    "unsupported type: " + typeToken));
            return;
        }
        String normalized = normalize(type, value);
        if (normalized == null) {
            rejected.add(new RejectedRecord(rawRecord, RejectionReason.INVALID_VALUE,
                    "value '" + value + "' is not a valid " + type));
            return;
        }
        int confidence = 50; // default when omitted
        if (confidenceStr != null && !confidenceStr.isBlank()) {
            try {
                confidence = Integer.parseInt(confidenceStr.trim());
                if (confidence < 0 || confidence > 100) {
                    throw new NumberFormatException("out of range");
                }
            } catch (NumberFormatException e) {
                rejected.add(new RejectedRecord(rawRecord, RejectionReason.INVALID_CONFIDENCE,
                        "confidence '" + confidenceStr + "' is not an integer in [0,100]"));
                return;
            }
        }
        Instant validFrom = parseInstant(validFromStr, "validFrom", rawRecord, rejected);
        if (validFrom == null && validFromStr != null && !validFromStr.isBlank()) {
            return;
        }
        Instant validUntil = parseInstant(validUntilStr, "validUntil", rawRecord, rejected);
        if (validUntil == null && validUntilStr != null && !validUntilStr.isBlank()) {
            return;
        }
        indicators.add(new Indicator(type, normalized, source.trim(), confidence,
                validFrom, validUntil, batchId));
    }

    private Instant parseInstant(String s, String field, String rawRecord, List<RejectedRecord> rejected) {
        if (s == null || s.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(s.trim());
        } catch (DateTimeParseException e) {
            rejected.add(new RejectedRecord(rawRecord, RejectionReason.INVALID_TIMESTAMP,
                    field + " '" + s + "' is not a valid ISO-8601 instant"));
            return null;
        }
    }

    /** Canonicalize a value for its type; returns null when invalid. */
    public static String normalize(IndicatorType type, String rawValue) {
        String v = rawValue.trim().toLowerCase(Locale.ROOT);
        return switch (type) {
            case IP -> isValidIpv4(v) || isValidIpv6(v) ? v : null;
            case DOMAIN -> DOMAIN.matcher(v).matches() ? v : null;
            case URL -> (v.startsWith("http://") || v.startsWith("https://")) && v.length() > 8
                    && !v.contains(" ") ? v : null;
            case EMAIL -> EMAIL.matcher(v).matches() ? v : null;
            case HASH_MD5 -> MD5.matcher(v).matches() ? v : null;
            case HASH_SHA1 -> SHA1.matcher(v).matches() ? v : null;
            case HASH_SHA256 -> SHA256.matcher(v).matches() ? v : null;
        };
    }

    private static boolean isValidIpv4(String v) {
        var m = IPV4.matcher(v);
        if (!m.matches()) {
            return false;
        }
        for (int i = 1; i <= 4; i++) {
            if (Integer.parseInt(m.group(i)) > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean isValidIpv6(String v) {
        // permissive check: hex groups and colons only, at least one colon
        return v.contains(":") && v.matches("^[0-9a-f:.%]+$");
    }
}
