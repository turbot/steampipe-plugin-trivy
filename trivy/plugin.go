package trivy

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

func Plugin(ctx context.Context) *plugin.Plugin {
	p := &plugin.Plugin{
		Name: "steampipe-plugin-trivy",
		ConnectionConfigSchema: &plugin.ConnectionConfigSchema{
			NewInstance: ConfigInstance,
			Schema:      ConfigSchema,
		},
		DefaultTransform: transform.FromGo().NullIfZero(),
		DefaultGetConfig: &plugin.GetConfig{
			//ShouldIgnoreError: isNotFoundError,
		},
		TableMap: map[string]*plugin.Table{
			"trivy_advisory":           tableTrivyAdvisory(ctx),
			"trivy_data_source":        tableTrivyDataSource(ctx),
			"trivy_dependency":         tableTrivyDependency(ctx),
			"trivy_scan_package":       tableTrivyScanPackage(ctx),
			"trivy_scan_secret":        tableTrivyScanSecret(ctx),
			"trivy_scan_vulnerability": tableTrivyScanVulnerability(ctx),
			"trivy_target":             tableTrivyTarget(ctx),
			"trivy_vulnerability":      tableTrivyVulnerability(ctx),
		},
	}
	return p
}
