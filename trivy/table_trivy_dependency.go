package trivy

import (
	"context"
	"encoding/json"

	gdpTypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
)

func tableTrivyDependency(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "trivy_dependency",
		Description: "Dependencies in the scanned artifacts.",
		List: &plugin.ListConfig{
			ParentHydrate: listTrivyTargetWithScan,
			Hydrate:       listTrivyDependency,
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "target", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "class", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "type", Type: proto.ColumnType_STRING, Description: ""},
			//
			{Name: "id", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "depends_on", Type: proto.ColumnType_JSON, Description: ""},
		},
	}
}

//// LIST FUNCTION

type dependencyRow struct {
	gdpTypes.Dependency
	Target string
	Class  types.ResultClass
	Type   string
}

func listTrivyDependency(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	target := h.Item.(types.Report)

	for _, result := range target.Results {
		j, _ := json.Marshal(result)
		plugin.Logger(ctx).Warn("listTrivyDependency", "result", string(j))
		/*
			for _, i := range result.Dependencies {
				vr := dependencyRow{
					i,
					result.Target,
					result.Class,
					result.Type,
				}
				d.StreamListItem(ctx, vr)
			}
		*/
	}

	return nil, nil
}
