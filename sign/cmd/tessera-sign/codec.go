package main

import (
	"encoding/json"

	"github.com/DAVANO-INNOVATION-LAB/tessera/sign/internal/bundle"
)

func marshalBundle(b *bundle.Bundle) ([]byte, error) {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func unmarshalBundle(data []byte) (*bundle.Bundle, error) {
	var b bundle.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}
