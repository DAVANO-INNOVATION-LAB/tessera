package parse

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// This is a deliberately tiny protobuf wire-format reader. Tessera reads ONNX
// (a serialized protobuf ModelProto) without the onnx or protobuf libraries on
// purpose: onnx.checker and an onnxruntime session both risk fetching external
// tensor data and resolving custom operator kernels — the exact behaviour the
// scan is meant to flag, not trigger. Walking the wire format by hand keeps the
// parse inert and lets us bound recursion depth and field count against the
// nested-message "protobuf bomb" denial-of-service class.

// Protobuf wire types.
const (
	wireVarint = 0
	wireI64    = 1
	wireLen    = 2
	wireI32    = 5
)

// pbGuards bound a walk so a hostile message cannot exhaust the scanner.
type pbGuards struct {
	maxDepth  int
	maxFields int
	fields    int // running total across the whole walk
}

func defaultGuards() *pbGuards {
	return &pbGuards{maxDepth: 24, maxFields: 5_000_000}
}

var errPBGuard = errors.New("protobuf walk exceeded safety limits")

// pbField is one decoded field: its number, wire type, and payload. For varint
// and fixed types the value is in num64; for length-delimited fields the bytes
// are in data.
type pbField struct {
	num   int
	wire  int
	num64 uint64
	data  []byte
}

// str returns a length-delimited field's bytes as a string.
func (f pbField) str() string { return string(f.data) }

// walk decodes the fields of a single protobuf message, calling fn for each. It
// does not recurse on its own — a handler recurses into a sub-message by
// calling walk again on the field's data, which lets each caller decide which
// branches are worth descending and keeps depth accounting explicit.
func walk(b []byte, g *pbGuards, depth int, fn func(pbField) error) error {
	if depth > g.maxDepth {
		return errPBGuard
	}
	for len(b) > 0 {
		g.fields++
		if g.fields > g.maxFields {
			return errPBGuard
		}
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return fmt.Errorf("bad field tag")
		}
		b = b[n:]
		fieldNum := int(tag >> 3)
		wire := int(tag & 0x7)

		var f pbField
		f.num = fieldNum
		f.wire = wire

		switch wire {
		case wireVarint:
			v, m := binary.Uvarint(b)
			if m <= 0 {
				return fmt.Errorf("bad varint")
			}
			b = b[m:]
			f.num64 = v
		case wireI64:
			if len(b) < 8 {
				return fmt.Errorf("truncated i64")
			}
			f.num64 = binary.LittleEndian.Uint64(b)
			b = b[8:]
		case wireI32:
			if len(b) < 4 {
				return fmt.Errorf("truncated i32")
			}
			f.num64 = uint64(binary.LittleEndian.Uint32(b))
			b = b[4:]
		case wireLen:
			l, m := binary.Uvarint(b)
			if m <= 0 {
				return fmt.Errorf("bad length prefix")
			}
			b = b[m:]
			if l > uint64(len(b)) {
				return fmt.Errorf("length-delimited field overruns message")
			}
			f.data = b[:l]
			b = b[l:]
		default:
			// Wire types 3/4 (start/end group) are deprecated and never appear
			// in ONNX; treat them as corruption rather than trying to skip.
			return fmt.Errorf("unsupported wire type %d", wire)
		}

		if err := fn(f); err != nil {
			return err
		}
	}
	return nil
}

// zigzag is unused by ONNX (which uses plain int64, not sint64) but kept for
// completeness of the reader; ONNX ir_version/model_version are wireVarint
// int64 read directly from num64.
func asInt64(v uint64) int64 { return int64(v) }
