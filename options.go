package tessera

import "github.com/DAVANO-INNOVATION-LAB/tessera/internal/parse"

// Option adjusts how an analysis runs. The zero-option default is the safe one:
// every physical file is hashed, and the bounds below are the parser's own.
// Options exist so an embedder with different constraints — a controller with a
// memory limit, a CI job that only wants metadata — can trade explicitly rather
// than by forking.
type Option func(*config)

type config struct {
	skipHashing bool
	maxFileSize int64
	maxFiles    int
}

func newConfig(opts []Option) config {
	cfg := config{
		maxFileSize: parse.DefaultMaxFileSize,
		maxFiles:    parse.DefaultMaxFiles,
	}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	return cfg
}

func (c config) parseOptions() parse.Options {
	return parse.Options{
		SkipHashing: c.skipHashing,
		MaxFileSize: c.maxFileSize,
		MaxFiles:    c.maxFiles,
	}
}

// WithoutHashing skips the SHA-256 pass over each physical file.
//
// Use it only when the hashes are not wanted, and know what it costs: hashing
// is what pins a component to specific bytes, and it is the field the CISA and
// G7 minimum elements for an SBOM require. A bill of materials produced without
// it names a model but does not identify one, so the resulting document is not
// a compliant SBOM. It is a reasonable trade for a fast metadata-only read.
func WithoutHashing() Option {
	return func(c *config) { c.skipHashing = true }
}

// WithMaxFileSize caps how many bytes any single file may occupy in memory
// during parsing. ONNX is the case that matters: it is protobuf, so the message
// is walked in memory, and a model larger than the cap is reported as a finding
// rather than being loaded. Zero or negative restores the default.
func WithMaxFileSize(n int64) Option {
	return func(c *config) {
		if n > 0 {
			c.maxFileSize = n
		}
	}
}

// WithMaxFiles caps how many physical files are gathered for one model. It
// bounds the work a directory of many shards can demand. Zero or negative
// restores the default.
func WithMaxFiles(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.maxFiles = n
		}
	}
}
