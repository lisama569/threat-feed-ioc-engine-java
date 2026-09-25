package com.github.lisama569.iocengine.model;

/**
 * A raw feed entry that was rejected, kept for later inspection.
 *
 * @param reason   machine-distinguishable rejection category
 * @param detail   human-readable explanation (which field, what was wrong)
 * @param rawContent the original unmodified content of the rejected entry
 */
public record RejectedEntry(RejectionReason reason, String detail, String rawContent) {
}
