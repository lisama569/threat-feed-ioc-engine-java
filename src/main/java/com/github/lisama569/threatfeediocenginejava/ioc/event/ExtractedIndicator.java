package com.github.lisama569.threatfeediocenginejava.ioc.event;

import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;

/**
 * One indicator extracted from raw event text.
 *
 * @param type            detected type
 * @param rawValue        substring as it appeared in the text
 * @param normalizedValue canonical form used for intel lookup
 */
public record ExtractedIndicator(IndicatorType type, String rawValue, String normalizedValue) {
}
