package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/quay/claircore"
	"io"
)

type Encoder interface {
	Encode(report *claircore.IndexReport) (any, error)
}

type Format string

const (
	JSON Format = "json"
)

func FromIndexReport(ir *claircore.IndexReport, e Encoder, f Format) (io.Reader, error) {
	result, err := e.Encode(ir)
	if err != nil {
		return nil, err
	}

	// TODO(DO NOT MERGE): Is this the correct data structure? Doesn't feel like it
	var buf bytes.Buffer

	switch f {
	case JSON:
		// TODO(DO NOT MERGE): What's the difference between this and doing a regular Marshal?
		if err := json.NewEncoder(&buf).Encode(result); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported format: %q", f)
	}

	return &buf, nil
}
