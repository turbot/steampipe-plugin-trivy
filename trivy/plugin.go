package trivy

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func Plugin(ctx context.Context) *plugin.Plugin {
	p := &plugin.Plugin{
		Name: "steampipe-plugin-trivy",
		ConnectionConfigSchema: &plugin.ConnectionConfigSchema{
			NewInstance: ConfigInstance,
		},
		DefaultTransform: transform.FromGo().NullIfZero(),
		DefaultGetConfig: &plugin.GetConfig{
			//ShouldIgnoreError: isNotFoundError,
		},
		TableMap: map[string]*plugin.Table{
			"trivy_advisory":           tableTrivyAdvisory(ctx),
			"trivy_data_source":        tableTrivyDataSource(ctx),
			"trivy_scan_artifact":      tableTrivyScanArtifact(ctx),
			"trivy_scan_package":       tableTrivyScanPackage(ctx),
			"trivy_scan_secret":        tableTrivyScanSecret(ctx),
			"trivy_scan_vulnerability": tableTrivyScanVulnerability(ctx),
			"trivy_vulnerability":      tableTrivyVulnerability(ctx),
		},
	}
	return p
}
