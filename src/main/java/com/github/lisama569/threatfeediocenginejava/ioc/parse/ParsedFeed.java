package com.github.lisama569.threatfeediocenginejava.ioc.parse;

import com.github.lisama569.threatfeediocenginejava.ioc.model.Indicator;
import com.github.lisama569.threatfeediocenginejava.ioc.model.RejectedRecord;

import java.util.List;

/**
 * Result of parsing one raw feed payload: normalized indicators plus rejected records.
 * Nothing is silently dropped — every input record ends up in exactly one of the two lists.
 */
public record ParsedFeed(List<Indicator> indicators, List<RejectedRecord> rejected) {
}
