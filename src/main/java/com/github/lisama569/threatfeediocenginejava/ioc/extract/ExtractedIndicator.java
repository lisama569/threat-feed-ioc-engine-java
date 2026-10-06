package com.github.lisama569.threatfeediocenginejava.ioc.extract;

import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;

/**
 * One indicator extracted from raw event text.
 *
 * @param type     indicator type
 * @param value    normalized (canonical) value
 * @param position character offset of the first occurrence in the event text
 */
public record ExtractedIndicator(IndicatorType type, String value, int position) {
}
