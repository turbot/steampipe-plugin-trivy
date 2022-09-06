package trivy

import (
	"context"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/turbot/steampipe-plugin-sdk/v4/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v4/plugin"
)

func tableTrivyScanSecret(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "trivy_scan_secret",
		Description: "Scan files and images for secrets.",
		List: &plugin.ListConfig{
			ParentHydrate: listTrivyScanArtifactWithScan,
			Hydrate:       listTrivyScanSecret,
			KeyColumns: []*plugin.KeyColumn{
				{Name: "artifact_name", Require: plugin.Optional, CacheMatch: "exact"},
				{Name: "artifact_type", Require: plugin.Optional},
			},
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "artifact_type", Type: proto.ColumnType_STRING, Description: "Type of artifact containing the package, e.g. container_image."},
			{Name: "artifact_name", Type: proto.ColumnType_STRING, Description: "Name of the artifact containing the package."},
			{Name: "target", Type: proto.ColumnType_STRING, Description: "Target within the artifact, e.g. library file or container image."},
			{Name: "rule_id", Type: proto.ColumnType_STRING, Description: "ID of the secret rule that was matched, e.g. private-key."},
			{Name: "category", Type: proto.ColumnType_STRING, Description: "Category of the secret rule that was matched."},
			{Name: "severity", Type: proto.ColumnType_STRING, Description: "Severity of the finding."},
			{Name: "title", Type: proto.ColumnType_STRING, Description: "Title of the finding."},
			{Name: "start_line", Type: proto.ColumnType_INT, Description: "Line number where the secret starts."},
			{Name: "end_line", Type: proto.ColumnType_INT, Description: "Line number where the secret ends."},
			{Name: "match", Type: proto.ColumnType_STRING, Description: "Matching string for the secret rule."},
		},
	}
}

type scanSecretRow struct {
	ArtifactType ftypes.ArtifactType
	ArtifactName string
	ftypes.SecretFinding
	Target string
	Class  types.ResultClass
	Type   string
}

func listTrivyScanSecret(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	target := h.Item.(types.Report)

	for _, result := range target.Results {
		for _, p := range result.Secrets {
			vr := scanSecretRow{
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
