package com.github.lisama569.threatfeediocenginejava.ioc.fp;

import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.model.Suppression;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * Local-only HTTP entry points for the analyst false-positive workflow.
 *
 * <ul>
 *   <li>{@code POST /ioc/false-positives} — body
 *       {@code {"type","value","reason","expiresAt"}}, {@code expiresAt} ISO-8601.</li>
 *   <li>{@code DELETE /ioc/false-positives?type=&value=} — revoke early.</li>
 * </ul>
 */
@RestController
@RequestMapping("/ioc/false-positives")
public class FalsePositiveController {

    /** Request body for creating a suppression. */
    public record SuppressRequest(String type, String value, String reason, String expiresAt) {
    }

    private final FalsePositiveService falsePositiveService;

    public FalsePositiveController(FalsePositiveService falsePositiveService) {
        this.falsePositiveService = falsePositiveService;
    }

    @PostMapping
    public Suppression suppress(@RequestBody SuppressRequest request) {
        if (request == null) {
            throw badRequest("request body is required");
        }
        IndicatorType type = IndicatorType.fromToken(request.type());
        if (type == null) {
            throw badRequest("unsupported type: " + request.type());
        }
        Instant expiresAt;
        try {
            expiresAt = Instant.parse(request.expiresAt());
        } catch (DateTimeParseException | NullPointerException e) {
            throw badRequest("expiresAt must be an ISO-8601 instant: " + request.expiresAt());
        }
        try {
            return falsePositiveService.suppress(type, request.value(), request.reason(), expiresAt);
        } catch (IllegalArgumentException e) {
            throw badRequest(e.getMessage());
        }
    }

    @DeleteMapping
    public boolean revoke(@RequestParam String type, @RequestParam String value) {
        IndicatorType t = IndicatorType.fromToken(type);
        if (t == null) {
            throw badRequest("unsupported type: " + type);
        }
        try {
            return falsePositiveService.revoke(t, value);
        } catch (IllegalArgumentException e) {
            throw badRequest(e.getMessage());
        }
    }

    private static ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
