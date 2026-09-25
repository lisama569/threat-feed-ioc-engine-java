package com.github.lisama569.iocengine.ingest;

import com.github.lisama569.iocengine.model.IngestResult;
import com.github.lisama569.iocengine.model.RejectedEntry;
import com.github.lisama569.iocengine.store.IocStore;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import java.util.stream.Collectors;

/** Coordinates parsing and storing of feed payloads. */
@Service
public class IngestService {

    private final Map<String, FeedParser> parsersByFormat;
    private final IocStore store;
    /** Audit log of every rejected entry (raw content preserved). */
    private final CopyOnWriteArrayList<RejectedEntry> rejections = new CopyOnWriteArrayList<>();

    public IngestService(List<FeedParser> parsers, IocStore store) {
        this.parsersByFormat = new ConcurrentHashMap<>(
                parsers.stream().collect(Collectors.toMap(FeedParser::format, Function.identity())));
        this.store = store;
    }

    /**
     * Ingest one feed payload. Safe to call concurrently with other ingests
     * and with matching: the store only exposes consistent snapshots.
     */
    public IngestResult ingest(String format, String batchId, String rawPayload) {
        FeedParser parser = parsersByFormat.get(format);
        if (parser == null) {
            throw new UnknownFormatException(format, parsersByFormat.keySet().toString());
        }
        String effectiveBatchId = (batchId == null || batchId.isBlank())
                ? UUID.randomUUID().toString()
                : batchId.trim();
        ParseOutcome outcome = parser.parse(effectiveBatchId, rawPayload);
        rejections.addAll(outcome.rejections());
        int accepted = store.merge(effectiveBatchId, outcome.records());
        return new IngestResult(effectiveBatchId, accepted,
                accepted == 0 && !outcome.records().isEmpty(),
                outcome.rejections());
    }

    /** All rejected entries seen so far, for audit/inspection. */
    public List<RejectedEntry> rejections() {
        return List.copyOf(rejections);
    }

    /** Thrown when the requested feed format has no registered parser. */
    public static class UnknownFormatException extends RuntimeException {
        public UnknownFormatException(String format, String supported) {
            super("unknown feed format '" + format + "'; supported: " + supported);
        }
    }
}
