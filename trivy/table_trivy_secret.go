package trivy

import (
	"context"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
)

func tableTrivySecret(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "trivy_secret",
		Description: "Secrets in the scanned artifacts.",
		List: &plugin.ListConfig{
			ParentHydrate: listTrivyTarget,
			Hydrate:       listTrivySecret,
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "target", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "class", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "type", Type: proto.ColumnType_STRING, Description: ""},
			//
			{Name: "rule_id", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "secret_rule_category", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "severity", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "title", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "start_line", Type: proto.ColumnType_INT, Description: ""},
			{Name: "end_line", Type: proto.ColumnType_INT, Description: ""},
			{Name: "match", Type: proto.ColumnType_STRING, Description: ""},
		},
	}
}

//// LIST FUNCTION

type secretRow struct {
	ftypes.SecretFinding
	Target string
	Class  types.ResultClass
	Type   string
}

func listTrivySecret(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	target := h.Item.(types.Report)

	for _, result := range target.Results {
		for _, p := range result.Secrets {
			vr := secretRow{
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
