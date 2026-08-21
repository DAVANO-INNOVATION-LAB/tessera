module github.com/DAVANO-INNOVATION-LAB/tessera/bundle

go 1.25.0

require github.com/DAVANO-INNOVATION-LAB/tessera/sign v0.2.0

require (
	github.com/cloudflare/circl v1.6.5 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// Resolved from the tree until the tagged version is published. A replace in
// a dependency is ignored by anything importing it, so this is local only.
replace github.com/DAVANO-INNOVATION-LAB/tessera/sign => ../sign
