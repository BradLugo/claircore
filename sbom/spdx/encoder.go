package spdx

import (
	"bytes"
	"container/heap"
	"context"
	"fmt"
	spdxjson "github.com/spdx/tools-golang/json"
	"io"
	"slices"
	"strconv"
	"strings"
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

	orderablePackages := &spdxPackageHeap{}
	seen := map[v2common.ElementID]interface{}{}
	var rels []*v2_3.Relationship
	for _, r := range ir.IndexRecords() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		packageSpdxId := v2common.ElementID("Package-" + r.Package.ID)

		// Record the package if we haven't seen it yet.
		if _, ok := seen[packageSpdxId]; !ok {
			pkgDB := ""
			for _, env := range ir.Environments[r.Package.ID] {
				if env.PackageDB != "" {
					pkgDB = env.PackageDB
					break
				}
			}

			orderablePkgId, err := strconv.Atoi(r.Package.ID)
			if err != nil {
				// TODO
				return nil, err
			}
			pkg := &v2_3.Package{
				PackageName:             r.Package.Name,
				PackageSPDXIdentifier:   packageSpdxId,
				PackageVersion:          r.Package.Version,
				PackageFileName:         pkgDB,
				PackageDownloadLocation: "NOASSERTION",
				FilesAnalyzed:           true,
				PrimaryPackagePurpose:   "APPLICATION",
			}

			orderablePkg := orderableSpdxPackage{
				recordType: claircorePackage,
				id:         orderablePkgId,
				pkg:        pkg,
			}

			heap.Push(orderablePackages, orderablePkg)
			seen[packageSpdxId] = struct{}{}

			if r.Package.Source != nil && r.Package.Source.Name != "" {
				srcPackageSpdxId := v2common.ElementID("Package-" + r.Package.Source.ID)

				// Record the source package if we haven't seen it yet.
				if _, ok := seen[srcPackageSpdxId]; !ok {
					orderableSrcPkgId, err := strconv.Atoi(r.Package.Source.ID)
					if err != nil {
						// TODO
						return nil, err
					}
					srcPkg := &v2_3.Package{
						PackageName:             r.Package.Source.Name,
						PackageSPDXIdentifier:   srcPackageSpdxId,
						PackageVersion:          r.Package.Source.Version,
						PackageDownloadLocation: "NOASSERTION",
						PrimaryPackagePurpose:   "SOURCE",
					}

					orderableSrcPkg := orderableSpdxPackage{
						recordType: claircorePackage,
						id:         orderableSrcPkgId,
						pkg:        srcPkg,
					}

					heap.Push(orderablePackages, orderableSrcPkg)
					seen[srcPackageSpdxId] = struct{}{}

					rels = append(rels, &v2_3.Relationship{
						RefA:         v2common.MakeDocElementID("", string(packageSpdxId)),
						RefB:         v2common.MakeDocElementID("", string(srcPackageSpdxId)),
						Relationship: "GENERATED_FROM",
					})
				}
			}
		}

		// Record Repositories for this package.
		if r.Repository != nil {
			repoSpdxId := v2common.ElementID("Repository-" + r.Repository.ID)
			if _, ok := seen[repoSpdxId]; !ok {
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

				orderableRepoId, err := strconv.Atoi(r.Repository.ID)
				if err != nil {
					// TODO
					return nil, err
				}
				repo := &v2_3.Package{
					PackageName:               r.Repository.Name,
					PackageSPDXIdentifier:     repoSpdxId,
					PackageDownloadLocation:   "NOASSERTION",
					FilesAnalyzed:             true,
					PackageSummary:            "repository",
					PackageExternalReferences: extRefs,
					PrimaryPackagePurpose:     "OTHER",
				}
				orderableSrcPkg := orderableSpdxPackage{
					recordType: claircoreRepository,
					id:         orderableRepoId,
					pkg:        repo,
				}
				heap.Push(orderablePackages, orderableSrcPkg)
				seen[repoSpdxId] = struct{}{}
			}
			rel := &v2_3.Relationship{
				RefA:         v2common.MakeDocElementID("", string(packageSpdxId)),
				RefB:         v2common.MakeDocElementID("", string(repoSpdxId)),
				Relationship: "CONTAINED_BY",
			}
			rels = append(rels, rel)
		}

		// Record Distributions for this package.
		if r.Distribution != nil {
			distroSpdxId := v2common.ElementID("Distribution-" + r.Distribution.ID)
			if _, ok := seen[distroSpdxId]; !ok {
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

				orderableDistroId, err := strconv.Atoi(r.Distribution.ID)
				if err != nil {
					// TODO
					return nil, err
				}
				dist := &v2_3.Package{
					PackageName:               r.Distribution.Name,
					PackageSPDXIdentifier:     distroSpdxId,
					PackageVersion:            r.Distribution.Version,
					PackageDownloadLocation:   "NOASSERTION",
					FilesAnalyzed:             true,
					PackageExternalReferences: extRefs,
					PackageSummary:            "distribution",
					PrimaryPackagePurpose:     "OPERATING-SYSTEM",
				}
				orderableSrcPkg := orderableSpdxPackage{
					recordType: claircoreDistribution,
					id:         orderableDistroId,
					pkg:        dist,
				}
				heap.Push(orderablePackages, orderableSrcPkg)
				seen[distroSpdxId] = struct{}{}
			}
			rel := &v2_3.Relationship{
				RefA:         v2common.MakeDocElementID("", string(packageSpdxId)),
				RefB:         v2common.MakeDocElementID("", string(distroSpdxId)),
				Relationship: "CONTAINED_BY",
			}
			rels = append(rels, rel)
		}
	}

	for orderablePackages.Len() > 0 {
		pkg := heap.Pop(orderablePackages).(orderableSpdxPackage).pkg
		out.Packages = append(out.Packages, pkg)
	}

	slices.SortFunc(rels, cmpRelationship)
	out.Relationships = rels

	return out, nil
}

func cmpRelationship(a, b *v2_3.Relationship) int {
	aRefAStr := string(a.RefA.ElementRefID)
	bRefAStr := string(b.RefA.ElementRefID)
	refACmp := strings.Compare(aRefAStr, bRefAStr)
	if refACmp != 0 {
		return refACmp
	}

	refBCpm := strings.Compare(string(a.RefB.ElementRefID), string(b.RefB.ElementRefID))
	if refBCpm != 0 {
		return refBCpm
	}

	return strings.Compare(a.Relationship, b.Relationship)
}
