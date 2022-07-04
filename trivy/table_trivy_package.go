package trivy

import (
	"context"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

func tableTrivyPackage(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "trivy_package",
		Description: "Packages in the scanned artifacts.",
		List: &plugin.ListConfig{
			ParentHydrate: listTrivyTarget,
			Hydrate:       listTrivyPackage,
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "target", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "class", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "type", Type: proto.ColumnType_STRING, Description: ""},
			//
			{Name: "id", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "name", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "version", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "release", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "epoch", Type: proto.ColumnType_INT, Description: ""},
			{Name: "arch", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "src_name", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "src_version", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "src_release", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "src_epoch", Type: proto.ColumnType_INT, Description: ""},
			{Name: "modularity_label", Type: proto.ColumnType_STRING, Transform: transform.FromField("Modularitylabel"), Description: ""},
			{Name: "build_info", Type: proto.ColumnType_JSON, Description: ""},
			{Name: "indirect", Type: proto.ColumnType_BOOL, Description: ""},
			{Name: "license", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "layer", Type: proto.ColumnType_JSON, Description: ""},
			{Name: "file_path", Type: proto.ColumnType_STRING, Description: ""},
		},
	}
}

//// LIST FUNCTION

type packageRow struct {
	ftypes.Package
	Target string
	Class  types.ResultClass
	Type   string
}

func listTrivyPackage(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	target := h.Item.(types.Report)

	for _, result := range target.Results {
		for _, p := range result.Packages {
			vr := packageRow{
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
