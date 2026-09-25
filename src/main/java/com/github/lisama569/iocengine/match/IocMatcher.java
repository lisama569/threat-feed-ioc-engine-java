package com.github.lisama569.iocengine.match;

import com.github.lisama569.iocengine.model.IocRecord;
import com.github.lisama569.iocengine.model.IocType;
import com.github.lisama569.iocengine.model.MatchVerdict;
import com.github.lisama569.iocengine.normalize.IocValues;
import com.github.lisama569.iocengine.store.IocStore;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts indicators from event text and looks them up in the store.
 *
 * <p>Lookup cost is O(1) per extracted candidate (hash map), independent of
 * the total number of stored indicators — matching does not degrade linearly
 * with feed size. Each distinct (type, value) in one event yields exactly one
 * verdict, so no duplicate hits are produced.
 */
@Component
public class IocMatcher {

    private static final Pattern URL = Pattern.compile("https?://[\\w.\\-]+(?::\\d{1,5})?(?:/\\S*)?",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern EMAIL = Pattern.compile("[\\w.+-]+@[\\w-]+(\\.[\\w-]+)+");
    private static final Pattern IPV4 = Pattern.compile("\\b\\d{1,3}(\\.\\d{1,3}){3}\\b");
    private static final Pattern SHA256 = Pattern.compile("\\b[0-9a-fA-F]{64}\\b");
    private static final Pattern SHA1 = Pattern.compile("\\b[0-9a-fA-F]{40}\\b");
    private static final Pattern MD5 = Pattern.compile("\\b[0-9a-fA-F]{32}\\b");
    private static final Pattern DOMAIN = Pattern.compile(
            "\\b([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,63}\\b");

    private final IocStore store;
    private final Clock clock;

    public IocMatcher(IocStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    /** Match one event; returns one verdict per distinct extracted indicator. */
    public List<MatchVerdict> match(String eventText) {
        Instant now = clock.instant();
        // LinkedHashMap keeps first-seen order and deduplicates by (type,value):
        // one verdict per distinct indicator, never a duplicate hit.
        Map<String, MatchVerdict> verdicts = new LinkedHashMap<>();
        if (eventText == null || eventText.isBlank()) {
            return List.of();
        }

        List<int[]> occupied = new ArrayList<>(); // spans claimed by URL/EMAIL matches

        extract(URL, eventText, IocType.URL, now, verdicts, occupied);
        extract(EMAIL, eventText, IocType.EMAIL, now, verdicts, occupied);
        extract(IPV4, eventText, IocType.IPV4, now, verdicts, null);
        extract(SHA256, eventText, IocType.SHA256, now, verdicts, null);
        extract(SHA1, eventText, IocType.SHA1, now, verdicts, null);
        extract(MD5, eventText, IocType.MD5, now, verdicts, null);
        // Domains: skip tokens already covered by a URL or email match.
        Matcher m = DOMAIN.matcher(eventText);
        while (m.find()) {
            if (insideAny(m.start(), m.end(), occupied)) {
                continue;
            }
            addVerdict(eventText.substring(m.start(), m.end()), IocType.DOMAIN, now, verdicts);
        }
        return List.copyOf(verdicts.values());
    }

    private void extract(Pattern pattern, String text, IocType type, Instant now,
                         Map<String, MatchVerdict> verdicts, List<int[]> occupied) {
        Matcher m = pattern.matcher(text);
        while (m.find()) {
            if (occupied != null) {
                occupied.add(new int[]{m.start(), m.end()});
            }
            addVerdict(m.group(), type, now, verdicts);
        }
    }

    private void addVerdict(String rawValue, IocType type, Instant now,
                            Map<String, MatchVerdict> verdicts) {
        // URLs may carry trailing punctuation from prose; strip it before normalizing.
        String cleaned = rawValue;
        if (type == IocType.URL) {
            cleaned = cleaned.replaceAll("[).,;!'\"]+$", "");
        }
        Optional<String> normalized = IocValues.normalize(type, cleaned);
        if (normalized.isEmpty()) {
            return; // candidate does not validate as this type; not an indicator
        }
        String key = type + "|" + normalized.get();
        verdicts.computeIfAbsent(key, k -> verdict(type, normalized.get(), now));
    }

    private MatchVerdict verdict(IocType type, String value, Instant now) {
        Optional<IocRecord> hit = store.lookup(type, value, now);
        if (hit.isEmpty()) {
            return MatchVerdict.miss(type, value,
                    "no live (non-expired) indicator for " + type + " '" + value + "'");
        }
        IocRecord r = hit.get();
        String expiry = r.expiresAt() == null ? "never expires" : "expires at " + r.expiresAt();
        return new MatchVerdict(true, type, value, r.source(), r.confidence(), r.expiresAt(),
                "matched " + type + " '" + value + "' reported by source '" + r.source()
                        + "' with confidence " + r.confidence() + "/100, " + expiry
                        + " (evaluated at " + now + ")");
    }

    private static boolean insideAny(int start, int end, List<int[]> spans) {
        for (int[] s : spans) {
            if (start >= s[0] && end <= s[1]) {
                return true;
            }
        }
        return false;
    }
}
