package sbom

import (
	"context"
	"io"

	"github.com/quay/claircore"
)

// Encoder is an interface to convert a claircore.IndexReport into an io.Reader
// that contains a Software Bill of Materials representation.
type Encoder interface {
	Encode(ctx context.Context, w io.Writer, ir *claircore.IndexReport) error
}
