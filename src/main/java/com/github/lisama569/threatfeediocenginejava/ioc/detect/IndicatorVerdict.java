package com.github.lisama569.threatfeediocenginejava.ioc.detect;

import com.github.lisama569.threatfeediocenginejava.ioc.fp.FalsePositiveRecord;
import com.github.lisama569.threatfeediocenginejava.ioc.model.Indicator;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;

/**
 * Verdict for one indicator extracted from an event.
 *
 * @param type          indicator type
 * @param value         normalized value
 * @param status        HIT (live intel matched), SUPPRESSED (matched but
 *                      dispositioned as false positive), or MISS
 * @param explanation   human-readable判定依据
 * @param indicator     the winning live indicator, or null when not matched
 * @param falsePositive the active suppression, or null
 */
public record IndicatorVerdict(IndicatorType type, String value, Status status,
                               String explanation, Indicator indicator,
                               FalsePositiveRecord falsePositive) {

    public enum Status {
        HIT,
        SUPPRESSED,
        MISS
    }
}
