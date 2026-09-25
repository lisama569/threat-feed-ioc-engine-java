package com.github.lisama569.threatfeediocenginejava.ioc.model;

/** Distinguishable reasons why a feed record was rejected during ingestion. */
public enum RejectionReason {
    /** The raw payload cannot be parsed as the declared feed format. */
    MALFORMED_FORMAT,
    /** A required field (type/value/source) is missing or blank. */
    MISSING_FIELD,
    /** The indicator type token is not supported. */
    UNSUPPORTED_TYPE,
    /** The indicator value fails type-specific validation/normalization. */
    INVALID_VALUE,
    /** A timestamp field cannot be parsed. */
    INVALID_TIMESTAMP,
    /** Confidence is not a number in [0, 100]. */
    INVALID_CONFIDENCE
}
