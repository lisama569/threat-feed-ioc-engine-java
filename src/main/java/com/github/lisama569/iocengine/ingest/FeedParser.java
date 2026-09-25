package com.github.lisama569.iocengine.ingest;

/** Parses one feed format into normalized records. Never throws on bad data. */
public interface FeedParser {

    /** Format identifier, e.g. "json" or "csv". */
    String format();

    /**
     * Parse the raw payload. Malformed entries are reported as rejections
     * (with their raw content preserved) instead of being dropped silently.
     */
    ParseOutcome parse(String batchId, String rawPayload);
}
