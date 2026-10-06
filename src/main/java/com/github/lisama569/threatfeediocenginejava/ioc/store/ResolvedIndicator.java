package com.github.lisama569.threatfeediocenginejava.ioc.store;

import com.github.lisama569.threatfeediocenginejava.ioc.model.Indicator;
import com.github.lisama569.threatfeediocenginejava.ioc.model.Suppression;

/**
 * Atomic resolution of one indicator at an instant: the winning live intel record
 * (when any) plus the false-positive suppression state. Both fields are observed
 * under the same store lock, so a detection can never see an intermediate state.
 *
 * @param indicator   winning live indicator, or null when no live intel exists
 * @param suppression currently effective suppression, or null when none
 */
public record ResolvedIndicator(Indicator indicator, Suppression suppression) {

    public boolean hit() {
        return indicator != null;
    }

    public boolean suppressed() {
        return indicator != null && suppression != null;
    }
}
