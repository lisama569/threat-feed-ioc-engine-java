package com.github.lisama569.threatfeediocenginejava.ioc;

import com.github.lisama569.threatfeediocenginejava.ioc.extract.ExtractedIndicator;
import com.github.lisama569.threatfeediocenginejava.ioc.extract.IocExtractor;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 业务点：事件原文指标识别 —— 多类型提取、归一化、去重、无指标文本。 */
class IocExtractorTest {

    private static final Logger log = LoggerFactory.getLogger(IocExtractorTest.class);

    private final IocExtractor extractor = new IocExtractor();

    @Test
    void extractsAllSupportedTypesFromOneEvent() {
        String event = "alert: host 203.0.113.7 contacted evil.example.com, "
                + "payload at http://mal.example.com/payload.exe, "
                + "sender attacker@bad.example.org, "
                + "md5 d41d8cd98f00b204e9800998ecf8427e "
                + "sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709 "
                + "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        List<ExtractedIndicator> found = extractor.extract(event);
        found.forEach(i -> log.info("extracted: {}={} @{}", i.type(), i.value(), i.position()));

        assertTrue(found.stream().anyMatch(i -> i.type() == IndicatorType.IP
                && i.value().equals("203.0.113.7")), "ip extracted");
        assertTrue(found.stream().anyMatch(i -> i.type() == IndicatorType.DOMAIN
                && i.value().equals("evil.example.com")), "domain extracted");
        assertTrue(found.stream().anyMatch(i -> i.type() == IndicatorType.URL
                && i.value().equals("http://mal.example.com/payload.exe")), "url extracted");
        assertTrue(found.stream().anyMatch(i -> i.type() == IndicatorType.EMAIL
                && i.value().equals("attacker@bad.example.org")), "email extracted");
        assertTrue(found.stream().anyMatch(i -> i.type() == IndicatorType.HASH_MD5), "md5 extracted");
        assertTrue(found.stream().anyMatch(i -> i.type() == IndicatorType.HASH_SHA1), "sha1 extracted");
        assertTrue(found.stream().anyMatch(i -> i.type() == IndicatorType.HASH_SHA256), "sha256 extracted");
    }

    @Test
    void repeatedIndicatorIsExtractedOnlyOnce() {
        String event = "src=198.51.100.23 dst=198.51.100.23 again 198.51.100.23";
        List<ExtractedIndicator> found = extractor.extract(event);
        long count = found.stream().filter(i -> i.type() == IndicatorType.IP
                && i.value().equals("198.51.100.23")).count();
        log.info("repeated ip extracted {} time(s): {}", count, found);
        assertEquals(1, count, "same indicator appearing many times counts once");
    }

    @Test
    void extractionIsDeterministicForSameInput() {
        String event = "see evil.example.com and 203.0.113.7, then evil.example.com again";
        List<ExtractedIndicator> first = extractor.extract(event);
        List<ExtractedIndicator> second = extractor.extract(event);
        log.info("run1={} run2={}", first, second);
        assertEquals(first, second, "same input must yield identical extraction");
    }

    @Test
    void textWithoutIndicatorsYieldsEmpty() {
        List<ExtractedIndicator> found = extractor.extract("nothing to see here, just words");
        log.info("no-ioc text -> {}", found);
        assertTrue(found.isEmpty(), "no extractable indicator");
        assertTrue(extractor.extract("").isEmpty(), "empty text");
        assertTrue(extractor.extract(null).isEmpty(), "null text");
    }

    @Test
    void invalidCandidatesAreNotExtracted() {
        // 999.1.1.1 fails IPv4 octet validation; bare word is not a domain
        List<ExtractedIndicator> found = extractor.extract("ip 999.1.1.1 and word test");
        log.info("invalid candidates -> {}", found);
        assertTrue(found.stream().noneMatch(i -> i.value().contains("999")),
                "invalid ipv4 must be rejected by canonical validation");
    }

    @Test
    void valuesAreNormalizedLikeIngestion() {
        List<ExtractedIndicator> found = extractor.extract("DOMAIN EVIL.Example.COM hash D41D8CD98F00B204E9800998ECF8427E");
        log.info("normalized -> {}", found);
        assertTrue(found.stream().anyMatch(i -> i.type() == IndicatorType.DOMAIN
                && i.value().equals("evil.example.com")), "domain lowercased");
        assertTrue(found.stream().anyMatch(i -> i.type() == IndicatorType.HASH_MD5
                && i.value().equals("d41d8cd98f00b204e9800998ecf8427e")), "hash lowercased");
    }
}
