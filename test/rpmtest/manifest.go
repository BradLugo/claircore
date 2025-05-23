package rpmtest

import (
	"encoding/json"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/quay/claircore"
)

type Manifest struct {
	RPM []ManifestRPM `json:"rpms"`
}
type ManifestRPM struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Release     string `json:"release"`
	Arch        string `json:"architecture"`
	SourceNEVRA string `json:"srpm_nevra"`
	SourceName  string `json:"srpm_name"`
	GPG         string `json:"gpg"`
	Module      string `json:"module"`
}

func PackagesFromRPMManifest(t *testing.T, r io.Reader) []*claircore.Package {
	t.Helper()
	var m Manifest
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		t.Fatal(err)
	}
	out := make([]*claircore.Package, 0, len(m.RPM))
	srcs := make([]claircore.Package, 0, len(m.RPM))
	src := make(map[string]*claircore.Package)
	for _, rpm := range m.RPM {
		p := claircore.Package{
			Name:           rpm.Name,
			Version:        rpm.Version + "-" + rpm.Release,
			Kind:           "binary",
			Arch:           rpm.Arch,
			RepositoryHint: "key:" + rpm.GPG,
			Module:         rpm.Module,
		}

		// Newer images produced from Konflux shove all the source information
		// into the SourceName and omit the SourceNEVRA. Try both.
		var source string
		switch {
		case rpm.SourceNEVRA != "":
			source = rpm.SourceNEVRA
		case rpm.SourceName != "":
			source = rpm.SourceName
		default:
			continue
		}

		if s, ok := src[source]; ok {
			p.Source = s
		} else {
			s := strings.TrimSuffix(strings.TrimSuffix(source, ".rpm"), ".src")
			pos := len(s)
			for i := 0; i < 2; i++ {
				pos = strings.LastIndexByte(s[:pos], '-')
				if pos == -1 {
					t.Fatalf("malformed NEVRA/NVRA: %q for %q", source, rpm.Name)
				}
			}
			idx := len(srcs)
			srcs = append(srcs, claircore.Package{
				Kind:    "source",
				Name:    s[:pos],
				Version: strings.TrimPrefix(s[pos+1:], "0:"),
				Module:  rpm.Module,
			})
			src[source] = &srcs[idx]
			p.Source = &srcs[idx]
		}

		out = append(out, &p)
	}
	return out
}

var Options = cmp.Options{
	HintCompare,
	EpochCompare,
	IgnorePackageDB,
	SortPackages,
	ModuleCompare,
}

// RPM Manifest doesn't have checksum information. It does have keyid information,
// so cook up a comparison function that understands the rpm package's packed format.
var HintCompare = cmp.FilterPath(
	func(p cmp.Path) bool { return p.Last().String() == ".RepositoryHint" },
	cmpopts.AcyclicTransformer("NormalizeHint", func(h string) string {
		n := [][2]string{}
		for _, s := range strings.Split(h, "|") {
			if s == "" {
				continue
			}
			k, v, ok := strings.Cut(s, ":")
			if !ok {
				panic("odd format: " + s)
			}
			if k == "hash" {
				continue
			}
			i := len(n)
			n = append(n, [2]string{})
			n[i][0] = k
			n[i][1] = v
		}
		sort.Slice(n, func(i, j int) bool { return n[i][0] < n[i][1] })
		var b strings.Builder
		for i, s := range n {
			if i != 0 {
				b.WriteByte('|')
			}
			b.WriteString(s[0])
			b.WriteByte(':')
			b.WriteString(s[1])
		}
		return b.String()
	}),
)

// RPM Manifest doesn't have package epoch information.
// This checks if the VR string is contained in the EVR string.
var EpochCompare = cmp.FilterPath(
	func(p cmp.Path) bool { return p.Last().String() == ".Version" },
	cmp.Comparer(func(a, b string) bool {
		evr, vr := a, b
		if len(b) > len(a) {
			evr = b
			vr = a
		}
		return strings.Contains(evr, vr)
	}),
)

// ModuleCompare allows one of the reported modules to be the empty string.
// This is needed because of [STONEBLD-1472].
//
// [STONEBLD-1472]: https://issues.redhat.com/browse/STONEBLD-1472
var ModuleCompare = cmp.FilterPath(
	func(p cmp.Path) bool { return p.Last().String() == ".Module" },
	cmp.FilterValues(
		func(a, b string) bool { return a != "" && b == "" || a == "" && b != "" },
		cmp.Ignore(),
	),
)

// Does what it says on the tin.
var (
	SortPackages = cmpopts.SortSlices(func(a, b *claircore.Package) bool {
		return a.Name < b.Name
	})
	IgnorePackageDB = cmpopts.IgnoreFields(claircore.Package{}, ".PackageDB")
)
