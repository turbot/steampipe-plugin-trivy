package trivy

import (
	"context"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func tableTrivyScanPackage(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "trivy_scan_package",
		Description: "Scan files and images for OS and language package versions.",
		List: &plugin.ListConfig{
			ParentHydrate: listTrivyScanArtifactWithScan,
			Hydrate:       listTrivyScanPackage,
			KeyColumns: []*plugin.KeyColumn{
				{Name: "artifact_name", Require: plugin.Optional, CacheMatch: "exact"},
				{Name: "artifact_type", Require: plugin.Optional},
			},
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "artifact_name", Type: proto.ColumnType_STRING, Description: "Name of the artifact containing the package."},
			{Name: "artifact_type", Type: proto.ColumnType_STRING, Description: "Type of artifact containing the package, e.g. container_image."},
			{Name: "target", Type: proto.ColumnType_STRING, Description: "Target within the artifact, e.g. library file or container image."},
			{Name: "class", Type: proto.ColumnType_STRING, Description: "Class of the package, e.g. lang-pkgs, os-pkgs."},
			{Name: "type", Type: proto.ColumnType_STRING, Description: "Type of the package, e.g. debian, ubuntu, yarn, npm, gomod."},
			{Name: "name", Type: proto.ColumnType_STRING, Description: "Name of the package, e.g. lodash."},
			{Name: "version", Type: proto.ColumnType_STRING, Description: "Version of the package, e.g. 4.13.4."},
			// Other columns
			{Name: "arch", Type: proto.ColumnType_STRING, Description: "Architecture for the package."},
			{Name: "build_info", Type: proto.ColumnType_JSON, Description: "Build info for the package. Only available for Red Hat."},
			{Name: "epoch", Type: proto.ColumnType_INT, Description: "Epoch of the package."},
			{Name: "file_path", Type: proto.ColumnType_STRING, Description: "File path to the package, if available."},
			{Name: "id", Type: proto.ColumnType_STRING, Description: "Identifier which can be used to reference the component elsewhere, e.g. lodash@4.13.4."},
			{Name: "indirect", Type: proto.ColumnType_BOOL, Description: "True if this package is an indirect dependency of the project."},
			{Name: "layer", Type: proto.ColumnType_JSON, Description: "Container image layer information, if available."},
			{Name: "licenses", Type: proto.ColumnType_JSON, Description: "License information, if available."},
			{Name: "modularity_label", Type: proto.ColumnType_STRING, Transform: transform.FromField("Modularitylabel"), Description: "Modularity label. Only available for Red Hat."},
			{Name: "ref", Type: proto.ColumnType_STRING, Description: "Identifier which can be used to reference the component elsewhere."},
			{Name: "release", Type: proto.ColumnType_STRING, Description: "Release of the package."},
			{Name: "src_epoch", Type: proto.ColumnType_INT, Description: "Epoch of the source package."},
			{Name: "src_name", Type: proto.ColumnType_STRING, Description: "Source package that installed this package, e.g. the 'shadow' source package installs 'passwd' and 'login' packages."},
			{Name: "src_release", Type: proto.ColumnType_STRING, Description: "Release of the source package that installed this package."},
			{Name: "src_version", Type: proto.ColumnType_STRING, Description: "Version of the source package that installed this package."},
		},
	}
}

type packageRow struct {
	ArtifactType ftypes.ArtifactType
	ArtifactName string
	ftypes.Package
	Target string
	Class  types.ResultClass
	Type   string
}

func listTrivyScanPackage(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	target := h.Item.(types.Report)

	for _, result := range target.Results {
		for _, p := range result.Packages {
			vr := packageRow{
				target.ArtifactType,
				target.ArtifactName,
				p,
				result.Target,
				result.Class,
				result.Type,
			}
			d.StreamListItem(ctx, vr)
		}
	}

	return nil, nil
}
