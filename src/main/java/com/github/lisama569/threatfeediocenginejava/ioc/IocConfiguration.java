package com.github.lisama569.threatfeediocenginejava.ioc;

import com.github.lisama569.threatfeediocenginejava.ioc.detect.EventDetectionService;
import com.github.lisama569.threatfeediocenginejava.ioc.extract.IocExtractor;
import com.github.lisama569.threatfeediocenginejava.ioc.fp.FalsePositiveRegistry;
import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchService;
import com.github.lisama569.threatfeediocenginejava.ioc.store.IndicatorStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.util.List;

/** Wires the IOC engine: source priority order, store, matcher, extractor, dispositions. */
@Configuration
public class IocConfiguration {

    @Bean
    public Clock iocClock() {
        return Clock.systemUTC();
    }

    @Bean
    public IndicatorStore indicatorStore(
            @Value("${ioc.source-priority:feedA,feedB,feedC}") List<String> sourcePriority) {
        return new IndicatorStore(sourcePriority);
    }

    @Bean
    public MatchService matchService(IndicatorStore store, Clock iocClock) {
        return new MatchService(store, iocClock);
    }

    @Bean
    public IocExtractor iocExtractor() {
        return new IocExtractor();
    }

    @Bean
    public FalsePositiveRegistry falsePositiveRegistry(Clock iocClock) {
        return new FalsePositiveRegistry(iocClock);
    }

    @Bean
    public EventDetectionService eventDetectionService(IocExtractor extractor, MatchService matcher,
                                                       FalsePositiveRegistry registry, Clock iocClock) {
        return new EventDetectionService(extractor, matcher, registry, iocClock);
    }
}
