package trivy

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

func tableTrivyTarget(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "trivy_target",
		Description: "Scanning targets.",
		List: &plugin.ListConfig{
			Hydrate: listTrivyTarget,
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "artifact_type", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "artifact_name", Type: proto.ColumnType_STRING, Description: ""},
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

/*
type targetRow struct {
	ArtifactType string
	ArtifactName string
}
*/

func listTrivyTarget(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {

	images := []string{"turbot/steampipe", "ubuntu:latest"}
	for _, i := range images {
		imageResult, err := scanTarget(ctx, "image", i)
		if err == nil {
			d.StreamListItem(ctx, imageResult)
		}
	}

	paths := []string{"/Users/nathan/src/steampipe-plugin-buildkite", "/Users/nathan/src/steampipe"}
	for _, i := range paths {
		imageResult, err := scanTarget(ctx, "fs", i)
		if err == nil {
			d.StreamListItem(ctx, imageResult)
		}
	}

	return nil, nil
}

func scanTarget(ctx context.Context, artifactType artifact.ArtifactType, targetName string) (types.Report, error) {

	opt := artifact.Option{
		GlobalOption: option.GlobalOption{
			CacheDir: "/Users/nathan/Library/Caches/trivy",
		},
		ArtifactOption: option.ArtifactOption{
			Target: targetName,
		},
		ReportOption: option.ReportOption{
			Severities:     []dbTypes.Severity{},
			SecurityChecks: []string{"secret", "unknown", "vuln", "config", "rbac"},
			VulnType:       []string{"os", "library", "unknown"},
			ListAllPkgs:    true,
		},
		DBOption: option.DBOption{
			DBRepository: "ghcr.io/aquasecurity/trivy-db",
		},
	}

	// TODO ScanRemovedPkgs: c.Bool("removed-pkgs"),
	// TODO IncludeNonFailures: c.Bool("include-non-failures"),

	sevStrings := []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	var severities []dbTypes.Severity
	for _, s := range sevStrings {
		severity, _ := dbTypes.NewSeverity(s)
		severities = append(severities, severity)
	}
	opt.ReportOption.Severities = severities

	plugin.Logger(ctx).Warn("trivy_target.listTrivyTarget", "targetName", targetName)
	plugin.Logger(ctx).Warn("trivy_target.listTrivyTarget", "artifactType", artifactType)
	plugin.Logger(ctx).Warn("trivy_target.listTrivyTarget", "opt", opt)

	/*
		ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
		defer cancel()

		defer func() {
			if xerrors.Is(err, context.DeadlineExceeded) {
				log.Logger.Warn("Increase --timeout value")
			}
		}()
	*/

	plugin.Logger(ctx).Warn("trivy_target.listTrivyTarget", "stage", "before runner")

	var report types.Report

	runner, err := artifact.NewRunner(opt)
	if err != nil {
		plugin.Logger(ctx).Error("trivy_target.listTrivyTarget", "connection_error", err)
		return report, err
	}
	defer runner.Close()

	plugin.Logger(ctx).Warn("trivy_target.listTrivyTarget", "stage", "before switch")

	switch artifactType {
	case containerImageArtifact, imageArchiveArtifact:
		if report, err = runner.ScanImage(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_target.listTrivyTarget", "scan_error", err)
			return report, err
		}
	case filesystemArtifact:
		if report, err = runner.ScanFilesystem(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_target.listTrivyTarget", "scan_error", err)
			return report, err
		}
	case rootfsArtifact:
		if report, err = runner.ScanRootfs(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_target.listTrivyTarget", "scan_error", err)
			return report, err
		}
	case repositoryArtifact:
		if report, err = runner.ScanRepository(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_target.listTrivyTarget", "scan_error", err)
			return report, err
		}
	}

	plugin.Logger(ctx).Warn("trivy_target.listTrivyTarget", "stage", "after switch")

	/*
		report, err = runner.Filter(ctx, opt, report)
		if err != nil {
			return xerrors.Errorf("filter error: %w", err)
		}
		if err = runner.Report(opt, report); err != nil {
			return xerrors.Errorf("report error: %w", err)
		}
	*/

	plugin.Logger(ctx).Warn("trivy_target.listTrivyTarget", "report", report.ArtifactName)

	plugin.Logger(ctx).Warn("trivy_target.listTrivyTarget", "stage", "before return")

	return report, nil
}
