package trivy

import (
	"context"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/option"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/urfave/cli/v2"

	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
)

func tableTrivyScanArtifact(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "trivy_scan_artifact",
		Description: "Container image and filesystem artifacts being scanned.",
		List: &plugin.ListConfig{
			Hydrate: listTrivyScanArtifactWithScan,
			KeyColumns: []*plugin.KeyColumn{
				{Name: "artifact_type", Require: plugin.Optional},
				{Name: "artifact_name", Require: plugin.Optional, CacheMatch: "exact"},
			},
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "artifact_name", Type: proto.ColumnType_STRING, Description: "Name of the artifact, e.g. turbot/steampipe (container image), /my/files (filesystem)."},
			{Name: "artifact_type", Type: proto.ColumnType_STRING, Description: "Type of the artifact, e.g. container_image, filesystem."},
			{Name: "metadata", Type: proto.ColumnType_JSON, Description: "Metadata from the container image."},
			{Name: "results", Type: proto.ColumnType_JSON, Description: "Detailed scan results, usually accessed through trivy_scan_* tables."},
		},
	}
}

const (
	containerImageArtifact artifact.ArtifactType = "image"
	filesystemArtifact     artifact.ArtifactType = "fs"
	rootfsArtifact         artifact.ArtifactType = "rootfs"
	repositoryArtifact     artifact.ArtifactType = "repo"
	imageArchiveArtifact   artifact.ArtifactType = "archive"
)

func listTrivyScanArtifactWithScan(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {

	keyQuals := d.KeyColumnQuals
	images := []string{}
	paths := []string{}

	var artifactType string
	if keyQuals["artifact_type"] != nil {
		artifactType = keyQuals["artifact_type"].GetStringValue()
	}

	if keyQuals["artifact_name"] != nil {
		// A specific artifact has been requested
		artifactName := keyQuals["artifact_name"].GetStringValue()

		switch artifactType {
		case "container_image":
			images = append(images, artifactName)
		case "filesystem":
			paths = append(paths, artifactName)
		default:
			images = append(images, artifactName)
			paths = append(paths, artifactName)
		}

	} else {
		// Use artifacts from the config

		config := GetConfig(d.Connection)
		plugin.Logger(ctx).Debug("trivy_artifact.listTrivyScanArtifact", "config", config)

		if &config != nil {
			switch artifactType {
			case "container_image":
				if config.Images != nil {
					images = config.Images
				}
			case "filesystem":
				if config.Paths != nil {
					paths = config.Paths
				}
			default:
				if config.Images != nil {
					images = config.Images
				}
				if config.Paths != nil {
					paths = config.Paths
				}
			}
		}
	}

	plugin.Logger(ctx).Debug("trivy_artifact.listTrivyScanArtifact", "images", images)
	plugin.Logger(ctx).Debug("trivy_artifact.listTrivyScanArtifact", "paths", paths)

	// Note: Artifact scanning is done in a serial fashion below. I tried moving this into
	// a separate hydrate function, but:
	// * It was actually slower in testing.
	// * It made reuse of artifact data in scan tables much harder.
	for _, i := range images {
		plugin.Logger(ctx).Debug("trivy_artifact.listTrivyScanArtifact", "scanningArtifactType", "image", "scanningArtifactName", i)
		imageResult, err := scanArtifact(ctx, d, "image", i)
		if err == nil {
			d.StreamListItem(ctx, imageResult)
		}
	}

	for _, i := range paths {
		plugin.Logger(ctx).Debug("trivy_artifact.listTrivyScanArtifact", "scanningArtifactType", "fs", "scanningArtifactName", i)
		imageResult, err := scanArtifact(ctx, d, "fs", i)
		if err == nil {
			d.StreamListItem(ctx, imageResult)
		}
	}

	return nil, nil
}

func scanArtifact(ctx context.Context, d *plugin.QueryData, artifactType artifact.ArtifactType, artifactName string) (types.Report, error) {

	plugin.Logger(ctx).Debug("trivy_artifact.scanArtifact", "artifactName", artifactName)
	plugin.Logger(ctx).Debug("trivy_artifact.scanArtifact", "artifactType", artifactType)

	cacheDir := GetConfigCacheDir(d.Connection)
	dbRepo := GetConfigDatabaseRepository(d.Connection)

	plugin.Logger(ctx).Debug("trivy_artifact.scanArtifact", "cacheDir", cacheDir)
	plugin.Logger(ctx).Debug("trivy_artifact.scanArtifact", "dbRepo", dbRepo)

	opt := artifact.Option{
		GlobalOption: option.GlobalOption{
			// Without context, Trivy crashes. So, mock their CLI context in a minimal way.
			Context: &cli.Context{
				Context: ctx,
			},
			// Use the cache dir as specified in the plugin config
			CacheDir: cacheDir,
		},
		// Artifact this specific artifact for scanning
		ArtifactOption: option.ArtifactOption{
			Target: artifactName,
		},
		// Get as much data as we can from the scan. In the future it may be worth only
		// targeting the data we need, but for now it's convenient to get everything
		// and manual testing didn't show a large performance impact.
		ReportOption: option.ReportOption{
			Severities:     []dbTypes.Severity{},
			SecurityChecks: []string{"secret", "unknown", "vuln", "config", "rbac"},
			VulnType:       []string{"os", "library", "unknown"},
			ListAllPkgs:    true,
		},
		// Database config
		DBOption: option.DBOption{
			DBRepository: dbRepo,
		},
	}

	// Severities need to be in the correct type
	sevStrings := []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	var severities []dbTypes.Severity
	for _, s := range sevStrings {
		severity, _ := dbTypes.NewSeverity(s)
		severities = append(severities, severity)
	}
	opt.ReportOption.Severities = severities

	// Logging for debug
	plugin.Logger(ctx).Debug("trivy_artifact.scanArtifact", "opt", opt)

	var report types.Report

	runner, err := artifact.NewRunner(opt)
	if err != nil {
		plugin.Logger(ctx).Error("trivy_artifact.scanArtifact", "run_error", err, "opt", opt)
		return report, err
	}
	defer runner.Close(ctx)

	switch artifactType {
	case containerImageArtifact, imageArchiveArtifact:
		if report, err = runner.ScanImage(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_artifact.scanArtifact", "artifactType", artifactType, "opt", opt, "scan_error", err)
			return report, err
		}
	case filesystemArtifact:
		if report, err = runner.ScanFilesystem(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_artifact.scanArtifact", "artifactType", artifactType, "opt", opt, "scan_error", err)
			return report, err
		}
	case rootfsArtifact:
		if report, err = runner.ScanRootfs(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_artifact.scanArtifact", "artifactType", artifactType, "opt", opt, "scan_error", err)
			return report, err
		}
	case repositoryArtifact:
		if report, err = runner.ScanRepository(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_artifact.scanArtifact", "artifactType", artifactType, "opt", opt, "scan_error", err)
			return report, err
		}
	}

	return report, nil
}
