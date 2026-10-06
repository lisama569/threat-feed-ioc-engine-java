package com.github.lisama569.threatfeediocenginejava.ioc.detect;

import java.util.List;

/**
 * Overall verdict for one raw event text.
 *
 * @param verdict    overall conclusion
 * @param indicators per-indicator verdicts (empty when nothing was extractable)
 * @param summary    human-readable overall explanation
 */
public record EventVerdict(Verdict verdict, List<IndicatorVerdict> indicators, String summary) {

    public enum Verdict {
        /** At least one extracted indicator hit live intel (not suppressed). */
        HIT,
        /** No live hit, but at least one hit was suppressed as a false positive. */
        SUPPRESSED,
        /** Indicators were found but none matched live intel. */
        NO_HIT,
        /** The event text contained no detectable indicator at all. */
        NO_INDICATORS
    }
}
