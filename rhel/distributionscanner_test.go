package rhel

import (
	"context"
	"github.com/quay/claircore"
	"github.com/quay/claircore/test"
	"github.com/quay/zlog"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
)

func TestDistributionScanner(t *testing.T) {
	sys := os.DirFS(`testdata/releasefiles`)
	ents, err := fs.ReadDir(sys, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		t.Run(e.Name(), func(t *testing.T) {
			n := path.Base(t.Name())
			sys, err := fs.Sub(sys, n)
			if err != nil {
				t.Fatal(err)
			}
			d, err := findDistribution(sys)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case strings.HasPrefix(n, "oracle-"):
				if d != nil {
					t.Fatalf("incorrect distribution: %s:%s", d.DID, d.VersionID)
				}
			default:
				if d == nil {
					t.Fatal("missing distribution")
				}
				if got, want := d.Version, strings.TrimPrefix(n, "atomichost-"); got != want {
					t.Errorf("got: %q, want %q", got, want)
				}
			}
		})
	}
}

func TestBootcDistributionDetection(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	f, err := os.Open(`testdata/layer-distro-links.tar`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	scanner := new(DistributionScanner)
	var l claircore.Layer
	desc := claircore.LayerDescription{
		Digest:    `sha256:` + strings.Repeat(`beef`, 16),
		URI:       `file:///dev/null`,
		MediaType: test.MediaType,
		Headers:   make(map[string][]string),
	}
	if err := l.Init(ctx, &desc, f); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error(err)
		}
	})
	distribution, err := scanner.Scan(ctx, &l)
	if err != nil {
		t.Fatal(err)
	}
	if distribution == nil {
		t.Fatal("nil distribution")
	}
}
