module github.com/DAVANO-INNOVATION-LAB/tessera/bench

go 1.25

require github.com/DAVANO-INNOVATION-LAB/tessera v0.4.7

// Resolved from the tree until the tagged version is published. A replace in a
// dependency is ignored by anything importing it, so this is local only.
replace github.com/DAVANO-INNOVATION-LAB/tessera => ..
