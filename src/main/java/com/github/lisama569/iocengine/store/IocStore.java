package com.github.lisama569.iocengine.store;

import com.github.lisama569.iocengine.model.IocRecord;
import com.github.lisama569.iocengine.model.IocType;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory store of indicators from all sources.
 *
 * <p>Determinism & concurrency guarantees:
 * <ul>
 *   <li>Each indicator key maps to an <b>immutable</b> list of per-source records,
 *       replaced wholesale inside {@link ConcurrentHashMap#compute}; readers therefore
 *       always see a consistent snapshot, never an intermediate merge state.</li>
 *   <li>Winner selection is a total order (source priority, confidence, expiry,
 *       source name), so the verdict for a key is reproducible.</li>
 *   <li>Batch ids are remembered; re-ingesting a batch is a no-op (no duplicate
 *       state, no duplicate counts).</li>
 *   <li>Expired records never win a lookup.</li>
 * </ul>
 */
@Component
public class IocStore {

    /** Indicator identity: normalized type + value. */
    public record IocKey(IocType type, String value) {
    }

    private final ConcurrentHashMap<IocKey, List<IocRecord>> byKey = new ConcurrentHashMap<>();
    private final Set<String> appliedBatches = ConcurrentHashMap.newKeySet();
    private final Map<String, Integer> sourcePriorities;

    public IocStore(@Qualifier("sourcePriorities") Map<String, Integer> sourcePriorities) {
        this.sourcePriorities = Map.copyOf(sourcePriorities);
    }

    /**
     * Merge records into the store. Idempotent per batchId.
     *
     * @return number of records actually merged (0 if the batch was already applied)
     */
    public int merge(String batchId, List<IocRecord> records) {
        if (!appliedBatches.add(batchId)) {
            return 0; // duplicate batch: no-op, no duplicate state or counts
        }
        int merged = 0;
        for (IocRecord rec : records) {
            IocKey key = new IocKey(rec.type(), rec.value());
            byKey.compute(key, (k, existing) -> {
                List<IocRecord> next = new ArrayList<>(existing == null ? List.of() : existing);
                // Same source re-reporting the same indicator replaces its old record
                // (latest observation wins within one source).
                next.removeIf(r -> r.source().equals(rec.source()));
                next.add(rec);
                return List.copyOf(next);
            });
            merged++;
        }
        return merged;
    }

    /**
     * Look up the winning record for an indicator at the given instant.
     * Expired records are excluded; if every record is expired the lookup misses.
     */
    public Optional<IocRecord> lookup(IocType type, String normalizedValue, Instant now) {
        List<IocRecord> snapshot = byKey.get(new IocKey(type, normalizedValue));
        if (snapshot == null) {
            return Optional.empty();
        }
        return snapshot.stream()
                .filter(r -> !r.isExpired(now))
                .max(winnerOrder());
    }

    /** Total order over records: deterministic and independent of ingestion order. */
    private Comparator<IocRecord> winnerOrder() {
        return Comparator
                .comparingInt((IocRecord r) -> sourcePriorities.getOrDefault(r.source(), 0))
                .thenComparingInt(IocRecord::confidence)
                // never-expiring (null) beats any finite expiry; later expiry beats earlier
                .thenComparing(r -> r.expiresAt() == null ? Instant.MAX : r.expiresAt())
                .thenComparing(IocRecord::source);
    }

    /** Total number of distinct indicator keys currently stored. */
    public int size() {
        return byKey.size();
    }

    /** Number of distinct batches applied so far. */
    public int appliedBatchCount() {
        return appliedBatches.size();
    }
}
