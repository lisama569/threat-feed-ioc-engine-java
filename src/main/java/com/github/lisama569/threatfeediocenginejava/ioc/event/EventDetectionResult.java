package com.github.lisama569.threatfeediocenginejava.ioc.event;

import java.util.List;

/**
 * Detection result for one raw event.
 *
 * @param eventId      caller-provided or generated id (nullable for single-text API)
 * @param rawText      the submitted event text
 * @param conclusion   overall event conclusion (never null)
 * @param extracted    number of distinct indicators extracted
 * @param hits         number of live intel hits (including suppressed ones)
 * @param suppressed   number of hits currently suppressed as false positives
 * @param verdicts     one verdict per distinct indicator, in first-occurrence order
 */
public record EventDetectionResult(String eventId, String rawText, EventConclusion conclusion,
                                   int extracted, int hits, int suppressed,
                                   List<IndicatorVerdict> verdicts) {
}
