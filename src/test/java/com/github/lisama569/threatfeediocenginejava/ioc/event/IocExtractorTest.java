package com.github.lisama569.threatfeediocenginejava.ioc.event;

import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Business point: raw text -> distinct, de-duplicated, validated IOC extraction. */
class IocExtractorTest {

    private static final Logger log = LoggerFactory.getLogger(IocExtractorTest.class);
    private final IocExtractor extractor = new IocExtractor();

    private List<String> keys(List<ExtractedIndicator> list) {
        return list.stream().map(e -> e.type() + "=" + e.normalizedValue()).toList();
    }

    @Test
    void extractsAllSupportedTypesFromMixedEventText() {
        String text = """
                Host 198.51.100.10 contacted evil.example.com and downloaded
                http://malware.example.org/payload.bin from user bad@phish.example.net.
                Sample hashes: md5=d41d8cd98f00b204e9800998ecf8427e
                sha1=da39a3ee5e6b4b0d3255bfef95601890afd80709
                sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
                """;
        List<ExtractedIndicator> got = extractor.extract(text);
        log.info("mixed text -> {}", keys(got));
        assertTrue(keys(got).contains("IP=198.51.100.10"));
        assertTrue(keys(got).contains("DOMAIN=evil.example.com"));
        assertTrue(keys(got).contains("URL=http://malware.example.org/payload.bin"));
        assertTrue(keys(got).contains("EMAIL=bad@phish.example.net"));
        assertTrue(keys(got).contains("HASH_MD5=d41d8cd98f00b204e9800998ecf8427e"));
        assertTrue(keys(got).contains("HASH_SHA1=da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        assertTrue(keys(got).contains(
                "HASH_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    }

    @Test
    void repeatedIndicatorIsCountedOnce() {
        String text = "198.51.100.10 ... 198.51.100.10 ... 198.51.100.10 again";
        List<ExtractedIndicator> got = extractor.extract(text);
        log.info("repeated ip -> {}", keys(got));
        assertEquals(1, got.size(), "same indicator repeated must be de-duplicated");
        assertEquals(IndicatorType.IP, got.get(0).type());
    }

    @Test
    void emptyOrIndicatorFreeTextExtractsNothing() {
        assertTrue(extractor.extract("").isEmpty());
        assertTrue(extractor.extract("   ").isEmpty());
        assertTrue(extractor.extract(null).isEmpty());
        List<ExtractedIndicator> got = extractor.extract(
                "plain prose with no indicators, version 1.2.3 (build 42) at 10:30.");
        log.info("indicator-free prose -> {}", keys(got));
        assertTrue(got.isEmpty(), "must not invent indicators from prose/version numbers");
    }

    @Test
    void urlIsNotAlsoCountedAsDomainOrIp() {
        String text = "see http://evil.example.com/path and https://198.51.100.5/x";
        List<ExtractedIndicator> got = extractor.extract(text);
        log.info("compound url -> {}", keys(got));
        assertEquals(2, got.size());
        assertEquals(IndicatorType.URL, got.get(0).type());
        assertEquals(IndicatorType.URL, got.get(1).type());
        assertFalse(keys(got).contains("DOMAIN=evil.example.com"));
        assertFalse(keys(got).contains("IP=198.51.100.5"));
    }

    @Test
    void emailIsNotAlsoCountedAsDomain() {
        List<ExtractedIndicator> got = extractor.extract("mail to bad@phish.example.net now");
        log.info("email -> {}", keys(got));
        assertEquals(1, got.size());
        assertEquals(IndicatorType.EMAIL, got.get(0).type());
    }

    @Test
    void invalidIpv4OctetsAreRejected() {
        List<ExtractedIndicator> got = extractor.extract("999.1.1.1 and 256.0.0.0 vs 127.0.0.1");
        log.info("ipv4 validation -> {}", keys(got));
        assertEquals(List.of("IP=127.0.0.1"), keys(got));
    }

    @Test
    void trailingSentencePunctuationIsStripped() {
        List<ExtractedIndicator> got = extractor.extract("C2 is evil.example.com, then done.");
        log.info("punctuation -> {}", keys(got));
        assertTrue(keys(got).contains("DOMAIN=evil.example.com"));
    }

    @Test
    void extractionIsDeterministicAcrossRuns() {
        String text = "b.example.com 1.2.3.4 a.example.com 1.2.3.4";
        List<String> first = keys(extractor.extract(text));
        List<String> second = keys(extractor.extract(text));
        log.info("run1={} run2={}", first, second);
        assertEquals(first, second, "same text must always extract the same ordered result");
        // deterministic first-occurrence order within each fixed extraction priority
        assertEquals(List.of("IP=1.2.3.4", "DOMAIN=b.example.com", "DOMAIN=a.example.com"), first);
        assertEquals(3, first.size(), "repeated ip still counts once");
    }
}
