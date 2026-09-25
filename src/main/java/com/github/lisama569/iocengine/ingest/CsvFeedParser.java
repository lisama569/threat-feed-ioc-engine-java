package com.github.lisama569.iocengine.ingest;

import com.github.lisama569.iocengine.model.IocRecord;
import com.github.lisama569.iocengine.model.IocType;
import com.github.lisama569.iocengine.model.RejectedEntry;
import com.github.lisama569.iocengine.model.RejectionReason;
import com.github.lisama569.iocengine.normalize.IocValues;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Parses CSV feeds with a header row. Required columns: type,value,source.
 * Optional columns: confidence,first_seen,expires_at. Extra columns are ignored.
 * Bad rows are rejected with their raw content preserved; parsing never throws.
 */
@Component
public class CsvFeedParser implements FeedParser {

    @Override
    public String format() {
        return "csv";
    }

    @Override
    public ParseOutcome parse(String batchId, String rawPayload) {
        List<IocRecord> records = new ArrayList<>();
        List<RejectedEntry> rejections = new ArrayList<>();
        if (rawPayload == null || rawPayload.isBlank()) {
            return new ParseOutcome(records, rejections);
        }
        String[] lines = rawPayload.split("\\R");
        List<String> header = splitRow(lines[0]);
        Map<String, Integer> col = new HashMap<>();
        for (int i = 0; i < header.size(); i++) {
            col.put(header.get(i).trim().toLowerCase(), i);
        }
        if (!col.containsKey("type") || !col.containsKey("value") || !col.containsKey("source")) {
            rejections.add(new RejectedEntry(RejectionReason.MISSING_FIELD,
                    "CSV header must contain columns: type,value,source", lines[0]));
            return new ParseOutcome(records, rejections);
        }
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isBlank()) {
                continue;
            }
            parseRow(batchId, line, col, records, rejections);
        }
        return new ParseOutcome(records, rejections);
    }

    private void parseRow(String batchId, String line, Map<String, Integer> col,
                          List<IocRecord> records, List<RejectedEntry> rejections) {
        List<String> cells = splitRow(line);
        if (cells.size() < col.size()) {
            rejections.add(new RejectedEntry(RejectionReason.MALFORMED_FORMAT,
                    "row has " + cells.size() + " columns, expected " + col.size(), line));
            return;
        }
        String typeRaw = cell(cells, col, "type");
        String valueRaw = cell(cells, col, "value");
        String source = cell(cells, col, "source");
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
        int confidence = 50;
        String confRaw = cell(cells, col, "confidence");
        if (confRaw != null) {
            try {
                confidence = Integer.parseInt(confRaw.trim());
                if (confidence < 0 || confidence > 100) {
                    throw new NumberFormatException("out of range");
                }
            } catch (NumberFormatException e) {
                rejections.add(new RejectedEntry(RejectionReason.INVALID_CONFIDENCE,
                        "confidence must be an integer in [0,100], got: '" + confRaw + "'", line));
                return;
            }
        }
        Instant firstSeen;
        try {
            firstSeen = parseInstant(cell(cells, col, "first_seen"), Instant.EPOCH);
        } catch (DateTimeParseException e) {
            rejections.add(new RejectedEntry(RejectionReason.INVALID_TIMESTAMP,
                    "first_seen is not a valid ISO-8601 timestamp", line));
            return;
        }
        Instant expiresAt;
        try {
            expiresAt = parseInstant(cell(cells, col, "expires_at"), null);
        } catch (DateTimeParseException e) {
            rejections.add(new RejectedEntry(RejectionReason.INVALID_TIMESTAMP,
                    "expires_at is not a valid ISO-8601 timestamp", line));
            return;
        }
        records.add(new IocRecord(type.get(), value.get(), source.trim(),
                confidence, firstSeen, expiresAt, batchId));
    }

    private static String cell(List<String> cells, Map<String, Integer> col, String name) {
        Integer idx = col.get(name);
        if (idx == null || idx >= cells.size()) {
            return null;
        }
        String s = cells.get(idx).trim();
        return s.isEmpty() ? null : s;
    }

    /** Minimal CSV row splitter supporting double-quoted fields. */
    static List<String> splitRow(String line) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        cur.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    cur.append(c);
                }
            } else if (c == '"') {
                inQuotes = true;
            } else if (c == ',') {
                out.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        out.add(cur.toString());
        return out;
    }

    private static Instant parseInstant(String raw, Instant defaultValue) {
        if (raw == null) {
            return defaultValue;
        }
        return Instant.parse(raw.trim());
    }
}
