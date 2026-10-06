package com.github.lisama569.threatfeediocenginejava.ioc.extract;

import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.FeedParser;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts IOC indicators (IPv4, domain, URL, email, MD5/SHA1/SHA256) from raw
 * event text. Extraction is deterministic: the same text always yields the
 * same indicators in the same (first-occurrence) order, and each distinct
 * (type, value) pair appears at most once no matter how often it occurs.
 *
 * Candidates are canonicalized with the exact same rules as feed ingestion
 * ({@link FeedParser#normalize}), so an extracted value always compares equal
 * to the stored form of the same indicator. IPv6 addresses are not extracted
 * from free text (too ambiguous); ingestion of IPv6 indicators is unaffected.
 */
public class IocExtractor {

    private static final Pattern URL = Pattern.compile(
            "https?://[^\\s\"'<>\\]})]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern EMAIL = Pattern.compile(
            "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,63}");
    private static final Pattern SHA256 = Pattern.compile("\\b[0-9a-fA-F]{64}\\b");
    private static final Pattern SHA1 = Pattern.compile("\\b[0-9a-fA-F]{40}\\b");
    private static final Pattern MD5 = Pattern.compile("\\b[0-9a-fA-F]{32}\\b");
    private static final Pattern IPV4 = Pattern.compile(
            "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b");
    private static final Pattern DOMAIN = Pattern.compile(
            "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                    + "(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+");

    /** Trailing characters that are almost always sentence punctuation, not URL content. */
    private static final String URL_TRAILING_NOISE = ".,;:!?'\"";

    /** Extraction passes in a fixed order; only used as a tie-break for equal positions. */
    private static final List<Pattern> PASS_ORDER =
            List.of(URL, EMAIL, SHA256, SHA1, MD5, IPV4, DOMAIN);

    private record Candidate(int position, int passOrder, IndicatorType type, String value) {
    }

    /** Extract and deduplicate indicators; null/blank text yields an empty list. */
    public List<ExtractedIndicator> extract(String eventText) {
        if (eventText == null || eventText.isBlank()) {
            return List.of();
        }
        List<Candidate> candidates = new ArrayList<>();
        for (int pass = 0; pass < PASS_ORDER.size(); pass++) {
            collect(eventText, PASS_ORDER.get(pass), pass, candidates);
        }
        candidates.sort(Comparator.comparingInt(Candidate::position)
                .thenComparingInt(Candidate::passOrder));
        Set<String> seen = new LinkedHashSet<>();
        List<ExtractedIndicator> result = new ArrayList<>();
        for (Candidate c : candidates) {
            if (seen.add(c.type() + "|" + c.value())) {
                result.add(new ExtractedIndicator(c.type(), c.value(), c.position()));
            }
        }
        return List.copyOf(result);
    }

    private void collect(String text, Pattern pattern, int passOrder, List<Candidate> out) {
        Matcher m = pattern.matcher(text);
        while (m.find()) {
            String raw = m.group();
            int endTrim = raw.length();
            if (pattern == URL) {
                while (endTrim > 0 && URL_TRAILING_NOISE.indexOf(raw.charAt(endTrim - 1)) >= 0) {
                    endTrim--;
                }
            }
            if (endTrim == 0) {
                continue;
            }
            IndicatorType type = typeOf(raw.substring(0, endTrim));
            if (type == null) {
                continue; // failed canonical validation (e.g. 999.1.1.1, numeric "domain")
            }
            out.add(new Candidate(m.start(), passOrder, type,
                    FeedParser.normalize(type, raw.substring(0, endTrim))));
        }
    }

    /** Classify a candidate by trying each type's canonical form; null when none fits. */
    private static IndicatorType typeOf(String raw) {
        for (IndicatorType type : IndicatorType.values()) {
            if (FeedParser.normalize(type, raw) != null) {
                return type;
            }
        }
        return null;
    }
}
