package com.github.lisama569.threatfeediocenginejava.ioc.event;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Local-only HTTP entry points for raw-event detection.
 *
 * <ul>
 *   <li>{@code POST /ioc/events/detect} — body is one raw event (plain text).</li>
 *   <li>{@code POST /ioc/events/detect-batch} — JSON {@link BatchDetectionRequest}.</li>
 * </ul>
 * The existing single-field {@code GET /ioc/match} behavior is unchanged.
 */
@RestController
@RequestMapping("/ioc")
public class EventDetectionController {

    private final EventDetectionService detectionService;

    public EventDetectionController(EventDetectionService detectionService) {
        this.detectionService = detectionService;
    }

    /** Detect one raw event; body is the raw event text. */
    @PostMapping("/events/detect")
    public EventDetectionResult detect(@RequestBody(required = false) String text) {
        return detectionService.detect(text);
    }

    /** Detect a batch of raw events; results keep submission order. */
    @PostMapping("/events/detect-batch")
    public List<EventDetectionResult> detectBatch(@RequestBody BatchDetectionRequest request) {
        return detectionService.detectBatch(request == null ? null : request.events());
    }
}
