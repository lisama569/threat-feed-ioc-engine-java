package com.github.lisama569.threatfeediocenginejava.ioc.event;

import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.FeedParser;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts IOCs (IP, domain, URL, email, MD5/SHA1/SHA256) from free-form event text.
 *
 * <p>Rules:
 * <ul>
 *   <li>Extraction is pure and deterministic; the same text always yields the same
 *       ordered list.</li>
 *   <li>Each distinct {@code (type, normalizedValue)} appears at most once no matter
 *       how many times it occurs; order is first occurrence in the text.</li>
 *   <li>Compound forms take priority over their sub-spans: URL first, then email,
 *       then hash/IP/domain, so a URL is not also counted as a domain/IP and an
 *       email not also as a domain.</li>
 *   <li>Candidates must pass the same type validation/normalization as ingested
 *       feeds (e.g. IPv4 octets ≤ 255, hash character set/length), so the store
 *       key space is identical.</li>
 * </ul>
 */
@Component
public class IocExtractor {

    private static final Pattern URL = Pattern.compile(
            "https?://[^\\s<>\"'\\)\\]\\}]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern EMAIL = Pattern.compile(
            "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,63}");
    private static final Pattern HASH = Pattern.compile(
            "(?<![A-Za-z0-9])[A-Fa-f0-9]{32}(?:[A-Fa-f0-9]{8})?(?:[A-Fa-f0-9]{24})?(?![A-Za-z0-9])");
    private static final Pattern IPV4 = Pattern.compile(
            "(?<![\\d.])(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})(?![\\d.])");
    private static final Pattern IPV6 = Pattern.compile(
            "(?<![0-9A-Fa-f:.])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![0-9A-Fa-f:.])");
    private static final Pattern DOMAIN = Pattern.compile(
            "(?<![A-Za-z0-9.@-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,63}(?![A-Za-z0-9-])");

    /** Extract distinct indicators in first-occurrence order. */
    public List<ExtractedIndicator> extract(String text) {
        // distinct key -> extracted value; LinkedHashMap preserves first-occurrence order
        Map<String, ExtractedIndicator> distinct = new LinkedHashMap<>();
        if (text == null || text.isBlank()) {
            return List.of();
        }
        // spans already claimed by a higher-priority compound form
        boolean[] claimed = new boolean[text.length()];
        scan(text, claimed, URL, IndicatorType.URL, distinct);
        scan(text, claimed, EMAIL, IndicatorType.EMAIL, distinct);
        scanHash(text, claimed, distinct);
        scanIpv4(text, claimed, distinct);
        scanIpv6(text, claimed, distinct);
        scanDomain(text, claimed, distinct);
        return new ArrayList<>(distinct.values());
    }

    private void scan(String text, boolean[] claimed, Pattern pattern, IndicatorType type,
                      Map<String, ExtractedIndicator> out) {
        Matcher m = pattern.matcher(text);
        while (m.find()) {
            if (overlapsClaimed(claimed, m.start(), m.end())) {
                continue;
            }
            String raw = cleanTrailing(m.group());
            addIfValid(text, m.start(), raw, type, claimed, out);
        }
    }

    private void scanHash(String text, boolean[] claimed, Map<String, ExtractedIndicator> out) {
        Matcher m = HASH.matcher(text);
        while (m.find()) {
            if (overlapsClaimed(claimed, m.start(), m.end())) {
                continue;
            }
            String raw = m.group();
            IndicatorType type = switch (raw.length()) {
                case 32 -> IndicatorType.HASH_MD5;
                case 40 -> IndicatorType.HASH_SHA1;
                case 64 -> IndicatorType.HASH_SHA256;
                default -> null;
            };
            if (type == null) {
                continue; // e.g. 48 hex chars: not a supported hash length
            }
            addIfValid(text, m.start(), raw, type, claimed, out);
        }
    }

    private void scanIpv4(String text, boolean[] claimed, Map<String, ExtractedIndicator> out) {
        Matcher m = IPV4.matcher(text);
        while (m.find()) {
            if (overlapsClaimed(claimed, m.start(), m.end())) {
                continue;
            }
            String raw = m.group();
            boolean octetsOk = true;
            for (int g = 1; g <= 4; g++) {
                if (Integer.parseInt(m.group(g)) > 255) {
                    octetsOk = false;
                    break;
                }
            }
            if (!octetsOk) {
                continue;
            }
            addIfValid(text, m.start(), raw, IndicatorType.IP, claimed, out);
        }
    }

    private void scanIpv6(String text, boolean[] claimed, Map<String, ExtractedIndicator> out) {
        Matcher m = IPV6.matcher(text);
        while (m.find()) {
            if (overlapsClaimed(claimed, m.start(), m.end())) {
                continue;
            }
            String raw = m.group();
            String normalized = FeedParser.normalize(IndicatorType.IP, raw);
            if (normalized == null || !raw.contains("::") && countColons(raw) < 2) {
                continue; // need at least two colons for a real IPv6 address
            }
            addValid(text, m.start(), m.end(), raw, normalized, IndicatorType.IP, claimed, out);
        }
    }

    private void scanDomain(String text, boolean[] claimed, Map<String, ExtractedIndicator> out) {
        Matcher m = DOMAIN.matcher(text);
        while (m.find()) {
            if (overlapsClaimed(claimed, m.start(), m.end())) {
                continue;
            }
            String raw = m.group();
            // require a letter in the TLD (rejects numeric suffixes / version-like strings)
            String tld = raw.substring(raw.lastIndexOf('.') + 1);
            if (!tld.matches(".*[A-Za-z].*")) {
                continue;
            }
            String normalized = FeedParser.normalize(IndicatorType.DOMAIN, raw);
            if (normalized == null) {
                continue;
            }
            addValid(text, m.start(), m.end(), raw, normalized, IndicatorType.DOMAIN, claimed, out);
        }
    }

    private void addIfValid(String text, int start, String raw, IndicatorType type,
                            boolean[] claimed, Map<String, ExtractedIndicator> out) {
        String normalized = FeedParser.normalize(type, raw);
        if (normalized == null) {
            return;
        }
        addValid(text, start, start + raw.length(), raw, normalized, type, claimed, out);
    }

    private void addValid(String text, int start, int end, String raw, String normalized,
                          IndicatorType type, boolean[] claimed, Map<String, ExtractedIndicator> out) {
        String key = type + "|" + normalized;
        if (!out.containsKey(key)) {
            out.put(key, new ExtractedIndicator(type, raw, normalized));
        }
        // mark the full original span (incl. stripped trailing punctuation) as claimed
        for (int i = start; i < end && i < claimed.length; i++) {
            claimed[i] = true;
        }
    }

    private static boolean overlapsClaimed(boolean[] claimed, int start, int end) {
        for (int i = start; i < end && i < claimed.length; i++) {
            if (claimed[i]) {
                return true;
            }
        }
        return false;
    }

    /** Drop trailing sentence punctuation that is not part of the indicator. */
    private static String cleanTrailing(String s) {
        int end = s.length();
        while (end > 0) {
            char c = s.charAt(end - 1);
            if (c == '.' || c == ',' || c == ';' || c == '!' || c == '?') {
                end--;
            } else {
                break;
            }
        }
        return s.substring(0, end);
    }

    private static int countColons(String s) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == ':') {
                n++;
            }
        }
        return n;
    }
}
