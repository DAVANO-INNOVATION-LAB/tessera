# tessera-bench

A labeled corpus and evaluator for Tessera's artifact analysis.

Every case is **generated from a declarative spec**, not committed as a binary.
Model files are large, and a corpus of checked-in blobs is one nobody can read,
diff, or reason about — the spec is both the fixture and the documentation of
what the case is for.

Each case carries expected findings and, more importantly, **forbidden** ones.
A benchmark that only measures what a tool finds rewards a tool that reports
everything; the traps are what make precision mean something.

    tessera-bench run                 # generate, scan, grade
    tessera-bench run --baseline b.json   # non-zero exit on regression
    tessera-bench generate --out DIR  # write the corpus and stop
