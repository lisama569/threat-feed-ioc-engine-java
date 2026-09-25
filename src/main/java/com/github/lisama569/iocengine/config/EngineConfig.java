package com.github.lisama569.iocengine.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class EngineConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    /**
     * Source priorities from property {@code ioc.source-priority},
     * e.g. "internal:100,partner-feed:50". Higher wins. Unknown sources get 0.
     */
    @Bean
    public Map<String, Integer> sourcePriorities(
            @Value("${ioc.source-priority:}") String spec) {
        Map<String, Integer> map = new HashMap<>();
        if (spec != null && !spec.isBlank()) {
            for (String entry : spec.split(",")) {
                String[] kv = entry.trim().split(":");
                if (kv.length == 2) {
                    map.put(kv[0].trim(), Integer.parseInt(kv[1].trim()));
                }
            }
        }
        return map;
    }
}
