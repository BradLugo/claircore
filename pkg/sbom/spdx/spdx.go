package spdx

import (
	"fmt"
	"runtime/debug"
	"time"

	"github.com/google/uuid"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/sbom"

	"github.com/spdx/tools-golang/convert"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_1"
	"github.com/spdx/tools-golang/spdx/v2/v2_2"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type Version string

const (
	V2_1 Version = "v2.1"
	V2_2 Version = "v2.2"
	V2_3 Version = "v2.3"
)

var _ sbom.Encoder = (*Encoder)(nil)

type Encoder struct {
	Version Version
}

// Encode encodes a claircore IndexReport to an io.Reader.
// We first convert the IndexReport to an SPDX doc of the latest version, then
// convert that doc to the specified version. We assume there's no data munging
// going from latest to the specified version.
func (e *Encoder) Encode(ir *claircore.IndexReport) (any, error) {
	spdx, err := parseIndexReport(ir)
	if err != nil {
		return nil, err
	}

	switch e.Version {
	case V2_1:
		var targetDoc v2_1.Document
		if err := convert.Document(spdx, targetDoc); err != nil {
			return nil, err
		}
		return targetDoc, nil
	case V2_2:
		var targetDoc v2_2.Document
		if err := convert.Document(spdx, targetDoc); err != nil {
			return nil, err
		}
		return targetDoc, nil
	case V2_3:
		// parseIndexReport currently returns a v2_3.Document so do nothing
		return spdx, nil
	}

	return nil, fmt.Errorf("unknown SPDX version: %v", e.Version)
}

func parseIndexReport(ir *claircore.IndexReport) (*v2_3.Document, error) {
	// Initial metadata
	out := &v2_3.Document{
		SPDXVersion:    v2_3.Version,
		DataLicense:    v2_3.DataLicense,
		SPDXIdentifier: "DOCUMENT",
		DocumentName:   ir.Hash.String(),
		// This would be nice to have but don't know how we'd get context w/o
		// having to accept it as an argument.
		// DocumentNamespace: "https://clairproject.org/spdxdocs/spdx-example-444504E0-4F89-41D3-9A0C-0305E82C3301",
		CreationInfo: &v2_3.CreationInfo{
			Creators: []common.Creator{
				{CreatorType: "Tool", Creator: "Claircore"},
				{CreatorType: "Organization", Creator: "Clair"},
			},
			Created: time.Now().Format("2006-01-02T15:04:05Z"),
		},
		DocumentComment: fmt.Sprintf("This document was created using claircore (%s).", getVersion()),
	}

	var rels []*v2_3.Relationship
	repoMap := map[string]*v2_3.Package{}
	distMap := map[string]*v2_3.Package{}
	pkgMap := map[string]*v2_3.Package{}
	fmt.Println(len(ir.IndexRecords()))
	for _, r := range ir.IndexRecords() {
		fmt.Println(r.Package.Name)
		if r.Repository == nil || r.Repository.ID == "" {
			continue
		}
		pkg, ok := pkgMap[r.Package.ID]
		if !ok {
			pkgDB := ""
			for _, e := range ir.Environments[r.Package.ID] {
				if e.PackageDB != "" {
					pkgDB = e.PackageDB
				}
			}
			pkg = &v2_3.Package{
				PackageName:             r.Package.Name,
				PackageSPDXIdentifier:   common.ElementID("pkg:" + r.Package.ID),
				PackageVersion:          r.Package.Version,
				PackageFileName:         pkgDB,
				PackageDownloadLocation: "NOASSERTION",
				FilesAnalyzed:           true,
			}
			pkgMap[r.Package.ID] = pkg
			out.Packages = append(out.Packages, pkg)

			if r.Package.Source != nil && r.Package.Source.Name != "" {
				srcPkg := &v2_3.Package{
					PackageName:           r.Package.Source.Name,
					PackageSPDXIdentifier: common.ElementID("src-pkg:" + r.Package.Source.ID),
					PackageVersion:        r.Package.Source.Version,
				}
				out.Packages = append(out.Packages, srcPkg)
				rels = append(rels, &v2_3.Relationship{
					RefA:         common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
					RefB:         common.MakeDocElementID("", string(srcPkg.PackageSPDXIdentifier)),
					Relationship: "GENERATED_FROM",
				})
			}
		}
		if r.Repository != nil {
			repo, ok := repoMap[r.Repository.ID]
			if !ok {
				repo = &v2_3.Package{
					PackageName:           r.Repository.Name,
					PackageSPDXIdentifier: common.ElementID("repo:" + r.Repository.ID),
					FilesAnalyzed:         true,
					PackageSummary:        "repository",
					PackageExternalReferences: []*v2_3.PackageExternalReference{
						{
							Category: "SECURITY",
							// TODO: always cpe:2.3?
							RefType: "cpe23Type",
							Locator: r.Repository.CPE.String(),
						},
						{
							Category: "OTHER",
							RefType:  "url",
							Locator:  r.Repository.URI,
						},
						{
							Category: "OTHER",
							RefType:  "key",
							Locator:  r.Repository.Key,
						},
					},
				}
				repoMap[r.Repository.ID] = repo
				out.Packages = append(out.Packages, repo)
			}
			rel := &v2_3.Relationship{
				RefA:         common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
				RefB:         common.MakeDocElementID("", string(repo.PackageSPDXIdentifier)),
				Relationship: "CONTAINED_BY",
			}
			rels = append(rels, rel)
		}
		if r.Distribution != nil {
			dist, ok := distMap[r.Distribution.ID]
			if !ok {
				dist = &v2_3.Package{
					PackageName:           r.Distribution.Name,
					PackageSPDXIdentifier: common.ElementID("dist:" + r.Distribution.ID),
					PackageVersion:        r.Distribution.Version,
					FilesAnalyzed:         true,
					PackageSummary:        "distribution",
					PackageExternalReferences: []*v2_3.PackageExternalReference{
						{
							Category: "SECURITY",
							// TODO: always cpe:2.3?
							RefType: "cpe23Type",
							Locator: r.Distribution.CPE.String(),
						},
						{
							Category: "OTHER",
							RefType:  "did",
							Locator:  r.Distribution.DID,
						},
						{
							Category: "OTHER",
							RefType:  "version_id",
							Locator:  r.Distribution.VersionID,
						},
						{
							Category: "OTHER",
							RefType:  "pretty_name",
							Locator:  r.Distribution.PrettyName,
						},
					},
				}
				distMap[r.Distribution.ID] = dist
				out.Packages = append(out.Packages, dist)
			}
			rel := &v2_3.Relationship{
				RefA:         common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
				RefB:         common.MakeDocElementID("", string(dist.PackageSPDXIdentifier)),
				Relationship: "CONTAINED_BY",
			}
			rels = append(rels, rel)
		}
	}

	layerMap := map[string]*v2_3.Package{}
	for pkgID, envs := range ir.Environments {
		for _, e := range envs {
			pkg, ok := layerMap[e.IntroducedIn.String()]
			if !ok {
				pkg = &v2_3.Package{
					PackageName:           e.IntroducedIn.String(),
					PackageSPDXIdentifier: common.ElementID(uuid.New().String()),
					FilesAnalyzed:         true,
					PackageSummary:        "layer",
				}
				out.Packages = append(out.Packages, pkg)
				layerMap[e.IntroducedIn.String()] = pkg
			}
			rel := &v2_3.Relationship{
				RefA:         common.MakeDocElementID("", pkgID),
				RefB:         common.MakeDocElementID("", string(pkg.PackageSPDXIdentifier)),
				Relationship: "CONTAINED_BY",
			}
			rels = append(rels, rel)
		}
	}
	out.Relationships = rels
	return out, nil
}

// GetVersion is copied from Clair and can hopefully give some
// context as to which revision of claircore was used.
func getVersion() string {
	info, infoOK := debug.ReadBuildInfo()
	var core string
	if infoOK {
		for _, m := range info.Deps {
			if m.Path != "github.com/quay/claircore" {
				continue
			}
			core = m.Version
			if m.Replace != nil && m.Replace.Version != m.Version {
				core = m.Replace.Version
			}
		}
	}
	if core == "" {
		core = "unknown revision"
	}
	return core
}
