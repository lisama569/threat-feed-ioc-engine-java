package com.github.lisama569.threatfeediocenginejava.ioc.event;

import java.util.List;

/**
 * Batch detection request: a list of raw events.
 *
 * @param events events to detect; each item carries an optional id and the raw text
 */
public record BatchDetectionRequest(List<EventItem> events) {

    /**
     * @param eventId optional correlation id
     * @param text    raw event text
     */
    public record EventItem(String eventId, String text) {
    }
}
