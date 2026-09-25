package com.github.lisama569.threatfeediocenginejava.ioc.match;

import com.github.lisama569.threatfeediocenginejava.ioc.model.Indicator;

/**
 * Outcome of matching one event field against the indicator store.
 *
 * @param matched     whether a live indicator matched
 * @param explanation human-readable判定依据: source, validity window, confidence — or why no match
 * @param indicator   the winning indicator, or null when not matched
 */
public record MatchResult(boolean matched, String explanation, Indicator indicator) {

    public static MatchResult hit(Indicator indicator, String explanation) {
        return new MatchResult(true, explanation, indicator);
    }

    public static MatchResult miss(String explanation) {
        return new MatchResult(false, explanation, null);
    }
}
