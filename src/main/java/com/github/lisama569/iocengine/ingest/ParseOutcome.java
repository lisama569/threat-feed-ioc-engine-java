package com.github.lisama569.iocengine.ingest;

import com.github.lisama569.iocengine.model.IocRecord;
import com.github.lisama569.iocengine.model.RejectedEntry;

import java.util.List;

/** Result of parsing one raw feed payload: normalized records plus rejections. */
public record ParseOutcome(List<IocRecord> records, List<RejectedEntry> rejections) {
}
