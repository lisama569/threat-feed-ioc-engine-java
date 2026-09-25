package com.github.lisama569.iocengine.api;

import com.github.lisama569.iocengine.match.IocMatcher;
import com.github.lisama569.iocengine.model.MatchVerdict;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/events")
public class MatchController {

    private final IocMatcher matcher;

    public MatchController(IocMatcher matcher) {
        this.matcher = matcher;
    }

    @PostMapping("/match")
    public List<MatchVerdict> match(@RequestBody String eventText) {
        return matcher.match(eventText);
    }
}
