package com.github.lisama569.threatfeediocenginejava.ioc.store;

import com.github.lisama569.threatfeediocenginejava.ioc.model.Indicator;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IndicatorType;
import com.github.lisama569.threatfeediocenginejava.ioc.model.IngestionResult;
import com.github.lisama569.threatfeediocenginejava.ioc.model.Suppression;
import com.github.lisama569.threatfeediocenginejava.ioc.parse.ParsedFeed;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe store of normalized indicators from multiple sources.
 *
 * Merge rule (deterministic and reproducible) for the same (type, value):
 *   1. higher source priority wins (earlier in the priority list = higher);
 *   2. tie -> higher confidence wins;
 *   3. tie -> later validUntil wins (longer-lived intel; null = never expires, wins);
 *   4. tie -> lexicographically smaller source name wins (stable total order).
 *
 * Expired indicators are never returned by lookups.
 * Re-importing the same batchId is idempotent: records already applied are
 * counted as duplicates and produce no state change.
 *
 * Concurrency: a batch is merged under the write lock, so readers never see
 * intermediate state; lookups run under the read lock and are O(1) hash lookups.
 */
public class IndicatorStore {

    private record Key(IndicatorType type, String value) {
    }

    private final Map<String, Integer> sourceRank = new HashMap<>();
    private final Map<Key, List<Indicator>> index = new HashMap<>();
    private final Map<Key, Suppression> suppressions = new HashMap<>();
    private final Set<String> appliedBatches = new HashSet<>();
    private final Set<String> appliedDedupKeys = new HashSet<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    /**
     * @param sourcePriority source names ordered from highest to lowest priority;
     *                       unknown sources rank below all listed ones.
     */
    public IndicatorStore(List<String> sourcePriority) {
        for (int i = 0; i < sourcePriority.size(); i++) {
            sourceRank.put(sourcePriority.get(i), i);
        }
    }

    /** Atomically merge a parsed batch. Returns per-batch statistics. */
    public IngestionResult ingest(String batchId, ParsedFeed feed) {
        lock.writeLock().lock();
        try {
            int accepted = 0;
            int duplicates = 0;
            int superseded = 0;
            for (Indicator ind : feed.indicators()) {
                if (!appliedDedupKeys.add(ind.dedupKey())) {
                    duplicates++; // same record from an already-imported batch
                    continue;
                }
                Key key = new Key(ind.type(), ind.value());
                List<Indicator> candidates = index.computeIfAbsent(key, k -> new ArrayList<>());
                Indicator before = winner(candidates);
                candidates.add(ind);
                Indicator after = winner(candidates);
                accepted++;
                if (before != after && before != null) {
                    superseded++;
                }
            }
            appliedBatches.add(batchId);
            return new IngestionResult(batchId, accepted, duplicates, superseded,
                    List.copyOf(feed.rejected()));
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Look up the winning LIVE indicator for (type, value) at the given instant.
     * Expired/not-yet-valid records are excluded from the candidate set, so a stale
     * record from a high-priority source can never shadow a still-live record from
     * a lower-priority source.
     */
    public Optional<Indicator> lookup(IndicatorType type, String value, Instant now) {
        lock.readLock().lock();
        try {
            return Optional.ofNullable(liveWinner(index.get(new Key(type, value)), now));
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Atomically resolve one indicator at {@code now}: winning live intel (if any)
     * plus the currently effective suppression (if any), observed under one read lock.
     * A detection therefore sees one consistent snapshot of intel + suppression and
     * can never observe an intermediate state.
     */
    public ResolvedIndicator resolve(IndicatorType type, String value, Instant now) {
        lock.readLock().lock();
        try {
            Key key = new Key(type, value);
            Indicator live = liveWinner(index.get(key), now);
            Suppression s = suppressions.get(key);
            if (s != null && !s.isActiveAt(now)) {
                s = null; // expired/revoked suppressions never suppress
            }
            return new ResolvedIndicator(live, s);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Install/replace the false-positive suppression for one indicator atomically.
     * Returns the suppression stored.
     */
    public Suppression putSuppression(IndicatorType type, String value, Suppression s) {
        Objects.requireNonNull(s, "suppression");
        lock.writeLock().lock();
        try {
            suppressions.put(new Key(type, value), s);
            return s;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Revoke the currently effective suppression for one indicator. Returns false
     * when no active suppression exists (unknown, already revoked, or expired).
     */
    public boolean revokeSuppression(IndicatorType type, String value, Instant now) {
        lock.writeLock().lock();
        try {
            Key key = new Key(type, value);
            Suppression s = suppressions.get(key);
            if (s == null || !s.isActiveAt(now)) {
                return false;
            }
            suppressions.put(key, s.revoked(now));
            return true;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** The currently effective suppression at {@code now}, or null. */
    public Optional<Suppression> currentSuppression(IndicatorType type, String value, Instant now) {
        lock.readLock().lock();
        try {
            Suppression s = suppressions.get(new Key(type, value));
            return s != null && s.isActiveAt(now) ? Optional.of(s) : Optional.empty();
        } finally {
            lock.readLock().unlock();
        }
    }

    /** Number of distinct (type, value) keys currently stored (including expired ones). */
    public int size() {
        lock.readLock().lock();
        try {
            return index.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    /** The deterministic winner among candidates for the same (type, value). */
    private Indicator winner(List<Indicator> candidates) {
        if (candidates == null || candidates.isEmpty()) {
            return null;
        }
        Indicator best = candidates.get(0);
        for (int i = 1; i < candidates.size(); i++) {
            if (compare(candidates.get(i), best) < 0) {
                best = candidates.get(i);
            }
        }
        return best;
    }

    /**
     * Deterministic winner among candidates that are LIVE at {@code now}.
     * Expired and not-yet-valid records are excluded before applying the total
     * order, so an expired high-priority record can never shadow a live one.
     */
    private Indicator liveWinner(List<Indicator> candidates, Instant now) {
        if (candidates == null || candidates.isEmpty()) {
            return null;
        }
        Indicator best = null;
        for (Indicator ind : candidates) {
            if (!ind.isLiveAt(now)) {
                continue;
            }
            if (best == null || compare(ind, best) < 0) {
                best = ind;
            }
        }
        return best;
    }

    /** Total order: negative = a wins over b. */
    private int compare(Indicator a, Indicator b) {
        int c = Integer.compare(rank(a.source()), rank(b.source()));
        if (c != 0) {
            return c;
        }
        c = Integer.compare(b.confidence(), a.confidence()); // higher confidence first
        if (c != 0) {
            return c;
        }
        c = compareValidUntil(a.validUntil(), b.validUntil());
        if (c != 0) {
            return c;
        }
        return a.source().compareTo(b.source());
    }

    private int rank(String source) {
        return sourceRank.getOrDefault(source, Integer.MAX_VALUE);
    }

    /** Later validUntil wins; null (never expires) is the largest. */
    private static int compareValidUntil(Instant a, Instant b) {
        if (a == null && b == null) {
            return 0;
        }
        if (a == null) {
            return -1;
        }
        if (b == null) {
            return 1;
        }
        return b.compareTo(a); // later first
    }

    /** Comparator exposed for tests/documentation of the merge rule. */
    public Comparator<Indicator> mergeOrder() {
        return this::compare;
    }
}
