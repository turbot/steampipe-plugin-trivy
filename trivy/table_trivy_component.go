package trivy

/*
import (
	"context"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/option"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

func tableTrivyComponent(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "trivy_component",
		Description: "Components in the scanned artifacts.",
		List: &plugin.ListConfig{
			Hydrate: listTrivyComponent,
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "raw", Type: proto.ColumnType_JSON, Transform: transform.FromValue(), Description: ""},
		},
	}
}

//// LIST FUNCTION

const (
	containerImageArtifact artifact.ArtifactType = "image"
	filesystemArtifact     artifact.ArtifactType = "fs"
	rootfsArtifact         artifact.ArtifactType = "rootfs"
	repositoryArtifact     artifact.ArtifactType = "repo"
	imageArchiveArtifact   artifact.ArtifactType = "archive"
)

func listTrivyComponent(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {

	var artifactType artifact.ArtifactType = "image"
	opt := artifact.Option{
		GlobalOption: option.GlobalOption{
			CacheDir: "/Users/nathan/Library/Caches/trivy",
		},
		ArtifactOption: option.ArtifactOption{
			Target: "turbot/steampipe",
		},
		ReportOption: option.ReportOption{
			Severities:     []dbTypes.Severity{},
			SecurityChecks: []string{"secret", "unknown", "vuln", "config"},
			VulnType:       []string{"os", "library"},
			ListAllPkgs:    true,
		},
		DBOption: option.DBOption{
			DBRepository: "ghcr.io/aquasecurity/trivy-db",
		},
	}

	artifactType = "fs"
	opt.ArtifactOption.Target = "/Users/nathan/src/steampipe"

	// TODO ScanRemovedPkgs: c.Bool("removed-pkgs"),
	// TODO IncludeNonFailures: c.Bool("include-non-failures"),

	sevStrings := []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	var severities []dbTypes.Severity
	for _, s := range sevStrings {
		severity, _ := dbTypes.NewSeverity(s)
		severities = append(severities, severity)
	}
	opt.ReportOption.Severities = severities

	plugin.Logger(ctx).Warn("trivy_component.listTrivyComponent", "artifactType", artifactType)
	plugin.Logger(ctx).Warn("trivy_component.listTrivyComponent", "opt", opt)

	runner, err := artifact.NewRunner(opt)
	if err != nil {
		plugin.Logger(ctx).Error("trivy_component.listTrivyComponent", "connection_error", err)
		return nil, err
	}
	defer runner.Close()

	var report types.Report
	switch artifactType {
	case containerImageArtifact, imageArchiveArtifact:
		if report, err = runner.ScanImage(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_component.listTrivyComponent", "scan_error", err)
			return nil, err
		}
	case filesystemArtifact:
		if report, err = runner.ScanFilesystem(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_component.listTrivyComponent", "scan_error", err)
			return nil, err
		}
	case rootfsArtifact:
		if report, err = runner.ScanRootfs(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_component.listTrivyComponent", "scan_error", err)
			return nil, err
		}
	case repositoryArtifact:
		if report, err = runner.ScanRepository(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_component.listTrivyComponent", "scan_error", err)
			return nil, err
		}
	}

	for _, i := range report.Results {
		d.StreamListItem(ctx, i)
	}

	return nil, nil
}

*/

/*



	conn, err := connect(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("trivy_component.listTrivyComponent", "connection_error", err)
		return nil, err
	}

	// URL parameters for all queries
	keyQuals := d.KeyColumnQuals

	var vsys, deviceGroup, name string
	var listing []addr.Entry
	var entry addr.Entry

	// Additional filters
	if d.KeyColumnQuals["name"] != nil {
		name = d.KeyColumnQuals["name"].GetStringValue()
		plugin.Logger(ctx).Trace("trivy_component.listTrivyComponent", "using name qual", name)
	}

	switch client := conn.(type) {
	case *pango.Firewall:
		{
			vsys = "vsys1"
			if keyQuals["vsys"] != nil {
				plugin.Logger(ctx).Trace("trivy_component.listTrivyComponent", "Firewall", "using vsys qual")
				vsys = keyQuals["vsys"].GetStringValue()
			}
			plugin.Logger(ctx).Trace("trivy_component.listTrivyComponent", "Firewall.vsys", vsys)

			// Filter using name, if passed in qual
			if name != "" {
				entry, err = client.Objects.Address.Get(vsys, name)
				listing = []addr.Entry{entry}
			} else {
				listing, err = client.Objects.Address.GetAll(vsys)
			}
		}
	case *pango.Panorama:
		{
			deviceGroup = "shared"
			if keyQuals["device_group"] != nil {
				plugin.Logger(ctx).Trace("trivy_component.listTrivyComponent", "Panorama", "using device_group qual")
				deviceGroup = keyQuals["device_group"].GetStringValue()
			}
			plugin.Logger(ctx).Trace("trivy_component.listTrivyComponent", "Panorama.device_group", deviceGroup)

			// Filter using name, if passed in qual
			if name != "" {
				entry, err = client.Objects.Address.Get(deviceGroup, name)
				listing = []addr.Entry{entry}
			} else {
				listing, err = client.Objects.Address.GetAll(deviceGroup)
			}
		}
	}

	if err != nil {
		plugin.Logger(ctx).Error("trivy_component.listTrivyComponent", "query_error", err)
		return nil, err
	}

	for _, i := range listing {
		d.StreamListItem(ctx, addressStruct{vsys, deviceGroup, i})
	}

	return nil, nil
}

*/
