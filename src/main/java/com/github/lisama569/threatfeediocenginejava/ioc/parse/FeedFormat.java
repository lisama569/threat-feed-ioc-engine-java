package com.github.lisama569.threatfeediocenginejava.ioc.parse;

/** Supported feed formats. */
public enum FeedFormat {
    /** JSON array of objects: [{"type":"ip","value":"1.2.3.4","source":"feedA","confidence":80,
     *  "validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-01-01T00:00:00Z"}, ...] */
    JSON,
    /** CSV with header row: type,value,source,confidence,validFrom,validUntil */
    CSV;

    /** Best-effort format detection from the payload's first non-blank character. */
    public static FeedFormat detect(String raw) {
        if (raw == null) {
            return null;
        }
        String t = raw.stripLeading();
        if (t.startsWith("[") || t.startsWith("{")) {
            return JSON;
        }
        if (!t.isEmpty()) {
            return CSV;
        }
        return null;
    }
}
