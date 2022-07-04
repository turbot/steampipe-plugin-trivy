package trivy

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

func tableTrivyResult(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "trivy_component",
		Description: "Vulnerabilities in the scanned artifacts.",
		List: &plugin.ListConfig{
			ParentHydrate: listTrivyTarget,
			Hydrate:       listTrivyResult,
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "raw", Type: proto.ColumnType_JSON, Transform: transform.FromValue(), Description: ""},
		},
	}
}

//// LIST FUNCTION

func listTrivyResult(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	target := h.Item.(types.Report)

	for _, result := range target.Results {
		d.StreamListItem(ctx, result)
	}

	return nil, nil
}
