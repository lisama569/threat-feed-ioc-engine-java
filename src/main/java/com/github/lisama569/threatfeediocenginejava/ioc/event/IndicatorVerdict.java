package com.github.lisama569.threatfeediocenginejava.ioc.event;

import com.github.lisama569.threatfeediocenginejava.ioc.model.Indicator;
import com.github.lisama569.threatfeediocenginejava.ioc.model.Suppression;

/**
 * Verdict for one distinct indicator found inside an event.
 *
 * @param status      HIT / SUPPRESSED_HIT / MISS
 * @param type        indicator type
 * @param value       normalized indicator value
 * @param indicator   winning live intel (present for HIT and SUPPRESSED_HIT)
 * @param suppression effective false-positive suppression (present only for SUPPRESSED_HIT)
 * @param explanation human-readable判定依据
 */
public record IndicatorVerdict(Status status, String type, String value,
                               Indicator indicator, Suppression suppression,
                               String explanation) {

    public enum Status {
        /** Live intel matched and no suppression applies. */
        HIT,
        /** Live intel matched, but the indicator is currently marked as a false positive. */
        SUPPRESSED_HIT,
        /** No live intel (unknown, expired, or not-yet-valid). */
        MISS
    }

    public boolean isHit() {
        return status != Status.MISS;
    }
}
