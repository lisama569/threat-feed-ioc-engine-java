package com.github.lisama569.iocengine.model;

/** Distinguishable reasons why a raw feed entry was rejected. */
public enum RejectionReason {
    /** The payload could not be parsed at all (broken JSON/CSV structure). */
    MALFORMED_FORMAT,
    /** A required field (type/value/source) is absent or blank. */
    MISSING_FIELD,
    /** The type field does not map to a supported IocType. */
    UNSUPPORTED_TYPE,
    /** The value does not conform to the declared type (e.g. bad IPv4). */
    INVALID_VALUE,
    /** A timestamp field exists but cannot be parsed. */
    INVALID_TIMESTAMP,
    /** Confidence is present but not a number in [0,100]. */
    INVALID_CONFIDENCE
}
