package com.github.lisama569.threatfeediocenginejava.ioc.model;

/**
 * A feed record that failed ingestion, retaining its raw content for later inspection.
 *
 * @param rawContent the original raw text of the rejected record
 * @param reason     classified rejection reason
 * @param detail     human-readable explanation (e.g. which field failed)
 */
public record RejectedRecord(String rawContent, RejectionReason reason, String detail) {
}
