package com.github.lisama569.iocengine.normalize;

import com.github.lisama569.iocengine.model.IocType;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Normalization and validation of indicator values.
 * Normalization is deterministic: same logical indicator always maps to
 * the same canonical string regardless of source formatting.
 */
public final class IocValues {

    private IocValues() {
    }

    private static final Pattern IPV4 = Pattern.compile(
            "^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$");
    private static final Pattern DOMAIN = Pattern.compile(
            "^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$");
    private static final Pattern URL = Pattern.compile(
            "^https?://[\\w.\\-]+(?::\\d{1,5})?(?:/\\S*)?$");
    private static final Pattern MD5 = Pattern.compile("^[0-9a-f]{32}$");
    private static final Pattern SHA1 = Pattern.compile("^[0-9a-f]{40}$");
    private static final Pattern SHA256 = Pattern.compile("^[0-9a-f]{64}$");
    private static final Pattern EMAIL = Pattern.compile(
            "^[\\w.+-]+@[\\w-]+(\\.[\\w-]+)+$");

    /**
     * Normalize a raw value for the given type.
     *
     * @return canonical value, or empty if the value is invalid for the type
     */
    public static Optional<String> normalize(IocType type, String rawValue) {
        if (rawValue == null) {
            return Optional.empty();
        }
        String v = rawValue.trim();
        if (v.isEmpty()) {
            return Optional.empty();
        }
        return switch (type) {
            case IPV4 -> IPV4.matcher(v).matches() ? Optional.of(v) : Optional.empty();
            case DOMAIN -> {
                String d = v.toLowerCase(Locale.ROOT);
                // strip a trailing dot (FQDN root label) for canonical form
                if (d.endsWith(".")) {
                    d = d.substring(0, d.length() - 1);
                }
                yield DOMAIN.matcher(d).matches() ? Optional.of(d) : Optional.empty();
            }
            case URL -> {
                String u = v.toLowerCase(Locale.ROOT);
                yield URL.matcher(u).matches() ? Optional.of(u) : Optional.empty();
            }
            case MD5 -> {
                String h = v.toLowerCase(Locale.ROOT);
                yield MD5.matcher(h).matches() ? Optional.of(h) : Optional.empty();
            }
            case SHA1 -> {
                String h = v.toLowerCase(Locale.ROOT);
                yield SHA1.matcher(h).matches() ? Optional.of(h) : Optional.empty();
            }
            case SHA256 -> {
                String h = v.toLowerCase(Locale.ROOT);
                yield SHA256.matcher(h).matches() ? Optional.of(h) : Optional.empty();
            }
            case EMAIL -> {
                String e = v.toLowerCase(Locale.ROOT);
                yield EMAIL.matcher(e).matches() ? Optional.of(e) : Optional.empty();
            }
        };
    }

    /** Parse a type name (case-insensitive, common aliases accepted). */
    public static Optional<IocType> parseType(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "ipv4", "ip", "ip-address", "ipv4-addr" -> Optional.of(IocType.IPV4);
            case "domain", "domain-name", "hostname" -> Optional.of(IocType.DOMAIN);
            case "url", "uri" -> Optional.of(IocType.URL);
            case "md5", "hash-md5" -> Optional.of(IocType.MD5);
            case "sha1", "hash-sha1" -> Optional.of(IocType.SHA1);
            case "sha256", "hash-sha256" -> Optional.of(IocType.SHA256);
            case "email", "email-addr", "mail" -> Optional.of(IocType.EMAIL);
            default -> Optional.empty();
        };
    }
}
