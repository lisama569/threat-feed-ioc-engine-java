package com.github.lisama569.threatfeediocenginejava.ioc.event;

import com.github.lisama569.threatfeediocenginejava.ioc.model.Indicator;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.model.Suppression;
import com.github.lisama569.threatfeediocenginejava.ioc.store.IndicatorStore;
import com.github.lisama569.threatfeediocenginejava.ioc.store.ResolvedIndicator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Detects indicators in raw event text against the intel store and produces an
 * explainable per-event conclusion.
 *
 * <p>Guarantees:
 * <ul>
 *   <li>Each distinct indicator in the event is resolved exactly once; repeated
 *       occurrences never create repeated verdicts.</li>
 *   <li>Every indicator is resolved atomically (live intel + suppression together)
 *       in {@link IndicatorStore}, so concurrent ingestion/suppression changes
 *       never produce an intermediate verdict.</li>
 *   <li>Expired/not-yet-valid intel can never hit; when multiple sources carry the
 *       same indicator and only some records are live, the verdict lands on a live
 *       record.</li>
 *   <li>A suppressed hit stays a visible {@code SUPPRESSED_HIT} with the original
 *       intel and the suppression reason/window — it never silently disappears.</li>
 *   <li>An event with no detectable indicators yields the explicit
 *       {@link EventConclusion#NO_DETECTABLE_INDICATORS} conclusion, never an empty
 *       response or an error.</li>
 *   <li>Same text at the same clock instant always yields the same result.</li>
 * </ul>
 */
public class EventDetectionService {

    private static final Logger log = LoggerFactory.getLogger(EventDetectionService.class);

    private final IocExtractor extractor;
    private final IndicatorStore store;
    private final Clock clock;

    public EventDetectionService(IocExtractor extractor, IndicatorStore store, Clock clock) {
        this.extractor = Objects.requireNonNull(extractor, "extractor");
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Detect one raw event (no caller id). */
    public EventDetectionResult detect(String text) {
        return detect(null, safe(text));
    }

    /** Detect one raw event with a correlation id. */
    public EventDetectionResult detect(String eventId, String text) {
        Instant now = clock.instant();
        List<ExtractedIndicator> extracted = extractor.extract(text);
        List<IndicatorVerdict> verdicts = new ArrayList<>(extracted.size());
        int hits = 0;
        int suppressed = 0;
        for (ExtractedIndicator e : extracted) {
            IndicatorVerdict verdict = resolveOne(e, now);
            verdicts.add(verdict);
            if (verdict.isHit()) {
                hits++;
                if (verdict.status() == IndicatorVerdict.Status.SUPPRESSED_HIT) {
                    suppressed++;
                }
            }
        }
        EventConclusion conclusion = conclude(extracted.size(), hits, suppressed);
        EventDetectionResult result = new EventDetectionResult(eventId, text, conclusion,
                extracted.size(), hits, suppressed, List.copyOf(verdicts));
        log.info("event detected: eventId={} conclusion={} extracted={} hits={} suppressed={}",
                eventId, conclusion, extracted.size(), hits, suppressed);
        verdicts.forEach(v -> log.info("  {} {}={} -> {}",
                v.status(), v.type(), v.value(), v.explanation()));
        return result;
    }

    /**
     * Detect a batch of raw events in submission order. {@code null} items or blank
     * text still get an explicit NO_DETECTABLE_INDICATORS result rather than failing.
     */
    public List<EventDetectionResult> detectBatch(List<BatchDetectionRequest.EventItem> events) {
        List<EventDetectionResult> results = new ArrayList<>();
        if (events == null) {
            return results;
        }
        for (int i = 0; i < events.size(); i++) {
            BatchDetectionRequest.EventItem item = events.get(i);
            String id = item != null && item.eventId() != null
                    ? item.eventId() : "event-" + i;
            String text = item == null ? null : safe(item.text());
            results.add(detect(id, text));
        }
        return results;
    }

    private IndicatorVerdict resolveOne(ExtractedIndicator e, Instant now) {
        ResolvedIndicator resolved = store.resolve(e.type(), e.normalizedValue(), now);
        Indicator ind = resolved.indicator();
        String typeName = e.type().name();
        if (ind == null) {
            return new IndicatorVerdict(IndicatorVerdict.Status.MISS, typeName,
                    e.normalizedValue(), null, null, String.format(
                    "no live indicator for %s=%s at %s (unknown or expired)",
                    typeName, e.normalizedValue(), now));
        }
        Suppression s = resolved.suppression();
        String base = String.format(
                "matched %s=%s | source=%s | confidence=%d | validFrom=%s | validUntil=%s | evaluatedAt=%s",
                ind.type(), ind.value(), ind.source(), ind.confidence(),
                ind.validFrom() == null ? "-inf" : ind.validFrom(),
                ind.validUntil() == null ? "+inf" : ind.validUntil(), now);
        if (s != null) {
            String why = String.format(
                    "%s | SUPPRESSED as false positive: reason=\"%s\" | suppressedAt=%s | expiresAt=%s",
                    base, s.reason(), s.createdAt(), s.expiresAt());
            return new IndicatorVerdict(IndicatorVerdict.Status.SUPPRESSED_HIT, typeName,
                    ind.value(), ind, s, why);
        }
        return new IndicatorVerdict(IndicatorVerdict.Status.HIT, typeName,
                ind.value(), ind, null, base);
    }

    private static EventConclusion conclude(int extracted, int hits, int suppressed) {
        if (extracted == 0) {
            return EventConclusion.NO_DETECTABLE_INDICATORS;
        }
        if (hits == 0) {
            return EventConclusion.NO_MATCH;
        }
        return hits == suppressed
                ? EventConclusion.ALL_HITS_SUPPRESSED
                : EventConclusion.THREAT_DETECTED;
    }

    private static String safe(String text) {
        return text == null ? "" : text;
    }
}
