package com.github.lisama569.threatfeediocenginejava.ioc.event;

/** Overall conclusion for one raw event. */
public enum EventConclusion {
    /** No detectable indicators could be extracted from the text. */
    NO_DETECTABLE_INDICATORS,
    /** At least one live hit that is not suppressed. */
    THREAT_DETECTED,
    /** Every live hit is suppressed as a false positive (and no unsuppressed hit exists). */
    ALL_HITS_SUPPRESSED,
    /** Detectable indicators existed, but none matched live intel. */
    NO_MATCH
}
