package spdx

import (
	"bytes"
	"context"
	"fmt"
	spdxjson "github.com/spdx/tools-golang/json"
	"io"
	"sort"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/sbom"

	"github.com/spdx/tools-golang/spdx/common"
	v2common "github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type Version string

const (
	V2_3 Version = "v2.3"
)

type Format string

const JSON Format = "json"

type Creator struct {
	Creator string
	// In accordance to the SPDX v2 spec, CreatorType should be one of "Person", "Organization", or "Tool"
	CreatorType string
}

var _ sbom.Encoder = (*Encoder)(nil)

type Encoder struct {
	Version           Version
	Format            Format
	Creators          []Creator
	DocumentName      string
	DocumentNamespace string
	DocumentComment   string
}

// Encode encodes a claircore IndexReport to an io.Reader.
// We first convert the IndexReport to an SPDX doc of the latest version, then
// convert that doc to the specified version. We assume there's no data munging
// going from latest to the specified version.
func (e *Encoder) Encode(ctx context.Context, ir *claircore.IndexReport) (io.Reader, error) {
	spdx, err := e.parseIndexReport(ctx, ir)
	if err != nil {
		return nil, err
	}

	// TODO(blugo): support SPDX versions before 2.3
	var tmpConverterDoc common.AnyDocument
	switch e.Version {
	case V2_3:
		// parseIndexReport currently returns a v2_3.Document so do nothing
		tmpConverterDoc = spdx
	default:
		return nil, fmt.Errorf("unknown SPDX version: %v", e.Version)
	}

	switch e.Format {
	case JSON:
		buf := &bytes.Buffer{}
		if err := spdxjson.Write(tmpConverterDoc, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}

	return nil, fmt.Errorf("unknown requested format: %v", e.Format)
}

func (e *Encoder) parseIndexReport(ctx context.Context, ir *claircore.IndexReport) (*v2_3.Document, error) {
	creatorInfo := e.Creators
	spdxCreators := make([]v2common.Creator, len(creatorInfo))
	for i, creator := range creatorInfo {
		spdxCreators[i].Creator = creator.Creator
		spdxCreators[i].CreatorType = creator.CreatorType
	}

	// Initial metadata
	out := &v2_3.Document{
		SPDXVersion:       v2_3.Version,
		DataLicense:       v2_3.DataLicense,
		SPDXIdentifier:    "DOCUMENT",
		DocumentName:      e.DocumentName,
		DocumentNamespace: e.DocumentNamespace,
		CreationInfo: &v2_3.CreationInfo{
			Creators: spdxCreators,
			Created:  time.Now().Format("2006-01-02T15:04:05Z"),
		},
		DocumentComment: e.DocumentComment,
	}

	var rels []*v2_3.Relationship
	repoMap := map[string]*v2_3.Package{}
	distMap := map[string]*v2_3.Package{}
	pkgMap := map[string]*v2_3.Package{}
	for _, r := range ir.IndexRecords() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// This could happen if the PackageScanner that found this package is
		// associated with two different Ecosystems and one of those Ecosystems
		// doesn't have the RepositoryScanner. If something like that happens,
		// we'll have the Repository information in another IndexRecord.
		//if r.Repository == nil || r.Repository.ID == "" {
		//	continue
		//}

		pkg, ok := pkgMap[r.Package.ID]

		// Record the package if we haven't seen it yet.
		if !ok {
			pkgDB := ""
			for _, env := range ir.Environments[r.Package.ID] {
				if env.PackageDB != "" {
					pkgDB = env.PackageDB
					break
				}
			}

			pkg = &v2_3.Package{
				PackageName:             r.Package.Name,
				PackageSPDXIdentifier:   v2common.ElementID("Package-" + r.Package.ID),
				PackageVersion:          r.Package.Version,
				PackageFileName:         pkgDB,
				PackageDownloadLocation: "NOASSERTION",
				FilesAnalyzed:           true,
				PrimaryPackagePurpose:   "APPLICATION",
			}
			pkgMap[r.Package.ID] = pkg
			//out.Packages = append(out.Packages, pkg)

			if r.Package.Source != nil && r.Package.Source.Name != "" {
				srcPkg := &v2_3.Package{
					PackageName:             r.Package.Source.Name,
					PackageSPDXIdentifier:   v2common.ElementID("Package-" + r.Package.Source.ID),
					PackageVersion:          r.Package.Source.Version,
					PackageDownloadLocation: "NOASSERTION",
					PrimaryPackagePurpose:   "SOURCE",
				}
				//out.Packages = append(out.Packages, srcPkg)
				// TODO(DO NOT MERGE): Is there a reason we don't want to put
				//  the source package here? It'll be skipped if we see it
				//  again, but is that a problem?
				pkgMap[r.Package.Source.ID] = srcPkg
				rels = append(rels, &v2_3.Relationship{
					RefA:         v2common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
					RefB:         v2common.MakeDocElementID("", string(srcPkg.PackageSPDXIdentifier)),
					Relationship: "GENERATED_FROM",
				})
			}
		}

		// Record Repositories for this package.
		if r.Repository != nil {
			repo, ok := repoMap[r.Repository.ID]
			if !ok {
				var extRefs []*v2_3.PackageExternalReference
				if r.Repository.CPE.String() != "" {
					extRefs = append(extRefs, &v2_3.PackageExternalReference{
						Category: "SECURITY",
						RefType:  "cpe23Type",
						Locator:  r.Repository.CPE.String(),
					})
				}

				if r.Repository.URI != "" {
					extRefs = append(extRefs, &v2_3.PackageExternalReference{
						Category: "OTHER",
						RefType:  "uri",
						Locator:  r.Repository.URI,
					})
				}

				if r.Repository.Key != "" {
					extRefs = append(extRefs, &v2_3.PackageExternalReference{
						Category: "OTHER",
						RefType:  "key",
						Locator:  r.Repository.Key,
					})
				}

				repo = &v2_3.Package{
					PackageName:               r.Repository.Name,
					PackageSPDXIdentifier:     v2common.ElementID("repo:" + r.Repository.ID),
					PackageDownloadLocation:   "NOASSERTION",
					FilesAnalyzed:             true,
					PackageSummary:            "repository",
					PackageExternalReferences: extRefs,
					PrimaryPackagePurpose:     "OTHER",
				}
				repoMap[r.Repository.ID] = repo
				//out.Packages = append(out.Packages, repo)
			}
			rel := &v2_3.Relationship{
				RefA:         v2common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
				RefB:         v2common.MakeDocElementID("", string(repo.PackageSPDXIdentifier)),
				Relationship: "CONTAINED_BY",
			}
			rels = append(rels, rel)
		}

		// Record Distributions for this package.
		if r.Distribution != nil {
			dist, ok := distMap[r.Distribution.ID]
			if !ok {
				var extRefs []*v2_3.PackageExternalReference

				if r.Distribution.CPE.String() != "" {
					extRefs = append(extRefs, &v2_3.PackageExternalReference{
						Category: "SECURITY",
						RefType:  "cpe23Type",
						Locator:  r.Distribution.CPE.String(),
					})
				}

				if r.Distribution.DID != "" {
					extRefs = append(extRefs, &v2_3.PackageExternalReference{
						Category: "OTHER",
						RefType:  "did",
						Locator:  r.Distribution.DID,
					})
				}

				if r.Distribution.VersionID != "" {
					extRefs = append(extRefs, &v2_3.PackageExternalReference{
						Category: "OTHER",
						RefType:  "version_id",
						Locator:  r.Distribution.VersionID,
					})
				}

				if r.Distribution.PrettyName != "" {
					extRefs = append(extRefs, &v2_3.PackageExternalReference{
						Category: "OTHER",
						RefType:  "pretty_name",
						Locator:  r.Distribution.PrettyName,
					})
				}

				dist = &v2_3.Package{
					PackageName:               r.Distribution.Name,
					PackageSPDXIdentifier:     v2common.ElementID("Distribution-" + r.Distribution.ID),
					PackageVersion:            r.Distribution.Version,
					PackageDownloadLocation:   "NOASSERTION",
					FilesAnalyzed:             true,
					PackageExternalReferences: extRefs,
					PackageSummary:            "distribution",
					PrimaryPackagePurpose:     "OPERATING-SYSTEM",
				}
				distMap[r.Distribution.ID] = dist
				//out.Packages = append(out.Packages, dist)
			}
			rel := &v2_3.Relationship{
				RefA:         v2common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
				RefB:         v2common.MakeDocElementID("", string(dist.PackageSPDXIdentifier)),
				Relationship: "CONTAINED_BY",
			}
			rels = append(rels, rel)
		}
	}

	// TODO(DO NOT MERGE): I don't love this but I couldn't think of another
	//  way to create a deterministic output to test against
	out.Packages = make([]*v2_3.Package, len(pkgMap)+len(distMap)+len(repoMap))

	i := 0
	for _, v := range pkgMap {
		for j := 0; j <= i; j++ {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if out.Packages[j] == nil {
				out.Packages[j] = v
				break
			}
			if string(v.PackageSPDXIdentifier) < string(out.Packages[j].PackageSPDXIdentifier) {
				out.Packages[j], out.Packages[j+1] = v, out.Packages[j]
				break
			}
		}
		i++
	}

	for _, v := range distMap {
		for j := len(pkgMap); j <= i; j++ {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if out.Packages[j] == nil {
				out.Packages[j] = v
				break
			}
			if string(v.PackageSPDXIdentifier) < string(out.Packages[j].PackageSPDXIdentifier) {
				out.Packages[j], out.Packages[j+1] = v, out.Packages[j]
				break
			}
		}
		i++
	}

	for _, v := range repoMap {
		for j := len(pkgMap) + len(distMap); j <= i; j++ {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if out.Packages[j] == nil {
				out.Packages[j] = v
				break
			}
			if string(v.PackageSPDXIdentifier) < string(out.Packages[j].PackageSPDXIdentifier) {
				out.Packages[j], out.Packages[j+1] = v, out.Packages[j]
				break
			}
		}
		i++
	}

	// TODO(DO NOT MERGE): Do we need to check the context? If not, we should remove it other places.
	//  If we do, we probably need to create a bespoke sorting method like above
	sort.SliceStable(rels, func(i, j int) bool {
		return rels[i].RefA.DocumentRefID <= rels[j].RefA.DocumentRefID || rels[i].RefA.DocumentRefID == rels[j].RefA.DocumentRefID && rels[i].RefB.DocumentRefID <= rels[j].RefB.DocumentRefID
	})

	out.Relationships = rels

	return out, nil
}
