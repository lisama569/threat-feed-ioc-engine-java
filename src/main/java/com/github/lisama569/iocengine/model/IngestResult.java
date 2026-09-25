package com.github.lisama569.iocengine.model;

import java.util.List;

/**
 * Outcome of ingesting one feed payload.
 *
 * @param batchId          id of the ingested batch (echoed or generated)
 * @param accepted         number of records merged into the store
 * @param duplicateBatch   true when this batchId was already ingested (no-op)
 * @param rejections       rejected entries with reasons and raw content
 */
public record IngestResult(
        String batchId,
        int accepted,
        boolean duplicateBatch,
        List<RejectedEntry> rejections
) {
}
