package com.github.lisama569.threatfeediocenginejava.ioc;

import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchResult;
import com.github.lisama569.threatfeediocenginejava.ioc.match.MatchService;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IngestionResult;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.FeedParser;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.ParsedFeed;
import com.github.lisama569.threatfeediocenginejava.ioc.store.IndicatorStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Local-only HTTP entry points for the ingest & detect flow. */
@RestController
@RequestMapping("/ioc")
public class IocController {

    private final FeedParser parser;
    private final IndicatorStore store;
    private final MatchService matcher;

    public IocController(FeedParser parser, IndicatorStore store, MatchService matcher) {
        this.parser = parser;
        this.store = store;
        this.matcher = matcher;
    }

    /** Ingest a raw feed payload (JSON array or CSV). Batch id makes re-import idempotent. */
    @PostMapping("/ingest")
    public IngestionResult ingest(@RequestBody String rawFeed,
                                  @RequestHeader("X-Batch-Id") String batchId) {
        ParsedFeed parsed = parser.parse(rawFeed, batchId);
        return store.ingest(batchId, parsed);
    }

    /** Match one event field; explanation always included. */
    @GetMapping("/match")
    public MatchResult match(@RequestParam String type, @RequestParam String value) {
        IndicatorType t = IndicatorType.fromToken(type);
        if (t == null) {
            return MatchResult.miss("unsupported type: " + type);
        }
        return matcher.match(t, value.trim().toLowerCase());
    }
}
