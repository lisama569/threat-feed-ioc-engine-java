package com.github.lisama569.threatfeediocenginejava.ioc;

import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchService;
import com.github.lisama569.threatfeediocenginejava.ioc.store.IndicatorStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.util.List;

/** Wires the IOC engine: source priority order, store, matcher. */
@Configuration
public class IocConfiguration {

    @Bean
    public IndicatorStore indicatorStore(
            @Value("${ioc.source-priority:feedA,feedB,feedC}") List<String> sourcePriority) {
        return new IndicatorStore(sourcePriority);
    }

    @Bean
    public MatchService matchService(IndicatorStore store) {
        return new MatchService(store, Clock.systemUTC());
    }

    @Bean
    public com.github.lisama569.threatfeediocenginejava.ioc.fp.FalsePositiveService
            falsePositiveService(IndicatorStore store) {
        return new com.github.lisama569.threatfeediocenginejava.ioc.fp.FalsePositiveService(
                store, Clock.systemUTC());
    }

    @Bean
    public com.github.lisama569.threatfeediocenginejava.ioc.event.EventDetectionService
            eventDetectionService(
                    com.github.lisama569.threatfeediocenginejava.ioc.event.IocExtractor extractor,
                    IndicatorStore store) {
        return new com.github.lisama569.threatfeediocenginejava.ioc.event.EventDetectionService(
                extractor, store, Clock.systemUTC());
    }
}
