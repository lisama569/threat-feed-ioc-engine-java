package com.github.lisama569.iocengine.api;

import com.github.lisama569.iocengine.ingest.IngestService;
import com.github.lisama569.iocengine.model.IngestResult;
import com.github.lisama569.iocengine.model.RejectedEntry;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/feeds")
public class IngestController {

    private final IngestService ingestService;

    public IngestController(IngestService ingestService) {
        this.ingestService = ingestService;
    }

    @PostMapping("/{format}")
    public IngestResult ingest(@PathVariable String format,
                               @RequestParam(required = false) String batchId,
                               @RequestBody String rawPayload) {
        return ingestService.ingest(format, batchId, rawPayload);
    }

    @GetMapping("/rejections")
    public List<RejectedEntry> rejections() {
        return ingestService.rejections();
    }

    @ExceptionHandler(IngestService.UnknownFormatException.class)
    public ResponseEntity<String> unknownFormat(IngestService.UnknownFormatException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
    }
}
