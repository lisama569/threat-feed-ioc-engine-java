package com.github.lisama569.threatfeediocenginejava.ioc.model;

import java.util.List;

/**
 * Outcome of ingesting one feed batch.
 *
 * @param batchId        the batch identifier supplied by the caller
 * @param accepted       number of indicators newly stored
 * @param duplicates     number of records skipped because the same batch was already imported
 * @param superseded     number of stored records that replaced a lower-priority/confidence record
 * @param rejected       records rejected with classified reasons and raw content
 */
public record IngestionResult(String batchId, int accepted, int duplicates, int superseded,
                              List<RejectedRecord> rejected) {

    public int totalRejected() {
        return rejected.size();
    }
}
