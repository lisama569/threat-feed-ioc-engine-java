package com.github.lisama569.threatfeediocenginejava.ioc.detect;

import com.github.lisama569.threatfeediocenginejava.ioc.extract.ExtractedIndicator;
import com.github.lisama569.threatfeediocenginejava.ioc.extract.IocExtractor;
import com.github.lisama569.threatfeediocenginejava.ioc.fp.FalsePositiveRecord;
import com.github.lisama569.threatfeediocenginejava.ioc.fp.FalsePositiveRegistry;
import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchResult;
import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchService;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Detects IOCs directly from raw event text: extract -> match each distinct
 * indicator once -> apply false-positive dispositions -> overall verdict.
 *
 * The whole event is evaluated at a single instant, so the same input always
 * yields the same verdict for the same store/registry state. A suppressed
 * indicator is still reported as a hit on live intel, with its status marked
 * SUPPRESSED — it never silently disappears from the result.
 */
public class EventDetectionService {

    private final IocExtractor extractor;
    private final MatchService matcher;
    private final FalsePositiveRegistry falsePositives;
    private final Clock clock;

    public EventDetectionService(IocExtractor extractor, MatchService matcher,
                                 FalsePositiveRegistry falsePositives, Clock clock) {
        this.extractor = extractor;
        this.matcher = matcher;
        this.falsePositives = falsePositives;
        this.clock = clock;
    }

    /** Detect a single raw event text. */
    public EventVerdict detect(String eventText) {
        Instant now = clock.instant();
        List<ExtractedIndicator> extracted = extractor.extract(eventText);
        if (extracted.isEmpty()) {
            return new EventVerdict(EventVerdict.Verdict.NO_INDICATORS, List.of(),
                    "no detectable indicator (ip/domain/url/email/md5/sha1/sha256) found in event text");
        }
        List<IndicatorVerdict> verdicts = new ArrayList<>(extracted.size());
        int hits = 0;
        int suppressed = 0;
        for (ExtractedIndicator e : extracted) {
            IndicatorVerdict v = judge(e, now);
            verdicts.add(v);
            if (v.status() == IndicatorVerdict.Status.HIT) {
                hits++;
            } else if (v.status() == IndicatorVerdict.Status.SUPPRESSED) {
                suppressed++;
            }
        }
        EventVerdict.Verdict overall = hits > 0 ? EventVerdict.Verdict.HIT
                : suppressed > 0 ? EventVerdict.Verdict.SUPPRESSED
                : EventVerdict.Verdict.NO_HIT;
        String summary = String.format(
                "event evaluatedAt=%s | indicators=%d | hit=%d | suppressed(falsePositive)=%d | miss=%d -> %s",
                now, verdicts.size(), hits, suppressed, verdicts.size() - hits - suppressed, overall);
        return new EventVerdict(overall, List.copyOf(verdicts), summary);
    }

    /** Detect a batch of raw event texts; one verdict per input, in order. */
    public List<EventVerdict> detectBatch(List<String> eventTexts) {
        List<EventVerdict> results = new ArrayList<>(eventTexts.size());
        for (String text : eventTexts) {
            results.add(detect(text));
        }
        return List.copyOf(results);
    }

    private IndicatorVerdict judge(ExtractedIndicator e, Instant now) {
        MatchResult match = matcher.match(e.type(), e.value(), now);
        if (!match.matched()) {
            return new IndicatorVerdict(e.type(), e.value(), IndicatorVerdict.Status.MISS,
                    match.explanation(), null, null);
        }
        Optional<FalsePositiveRecord> fp =
                falsePositives.activeSuppression(e.type(), e.value(), now);
        if (fp.isPresent()) {
            FalsePositiveRecord f = fp.get();
            String explanation = String.format(
                    "%s | SUPPRESSED as false positive | reason=%s | markedAt=%s | suppressionValidUntil=%s",
                    match.explanation(), f.reason(), f.markedAt(), f.validUntil());
            return new IndicatorVerdict(e.type(), e.value(), IndicatorVerdict.Status.SUPPRESSED,
                    explanation, match.indicator(), f);
        }
        return new IndicatorVerdict(e.type(), e.value(), IndicatorVerdict.Status.HIT,
                match.explanation(), match.indicator(), null);
    }
}
