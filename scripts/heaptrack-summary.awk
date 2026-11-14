# Shortens `heaptrack_print -m 0` output for `make profile-mem`: each top allocation site is
# shown at its first frame in Wirdigen's crates, then the totals (peak heap, allocations,
# temporary allocations). `heaptrack_gui` has the full backtraces.

function flush() {
    if (entry != "") {
        print "  " entry
        print "      " (site != "" ? site : "outside Wirdigen's crates")
    }
    entry = ""
    site = ""
}

/^(PEAK MEMORY CONSUMERS|MOST CALLS TO ALLOCATION FUNCTIONS|MOST TEMPORARY ALLOCATIONS)$/ {
    flush()
    print ""
    print
    next
}

/^total runtime/ {
    flush()
    print ""
    totals = 1
}

totals { print; next }

/^[0-9]/ {
    flush()
    entry = $0
    sub(/ from$/, "", entry)
    next
}

entry != "" && site == "" && /^ +at .*crates\/wirdigen/ {
    site = $0
    sub(/^ +at .*crates\//, "at crates/", site)
}
