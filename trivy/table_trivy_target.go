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

func tableTrivyTarget(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "trivy_target",
		Description: "Scanning targets.",
		List: &plugin.ListConfig{
			Hydrate: listTrivyTarget,
			//Hydrate: listTrivyTargetWithScan,
			KeyColumns: []*plugin.KeyColumn{
				{Name: "artifact_type", Require: plugin.Optional},
				{Name: "artifact_name", Require: plugin.Optional},
			},
		},
		Columns: []*plugin.Column{
			// Top columns
			//{Name: "artifact_type", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "artifact_type", Type: proto.ColumnType_STRING, Hydrate: scanTarget, Description: ""},
			{Name: "artifact_name", Type: proto.ColumnType_STRING, Description: ""},
			//{Name: "metadata", Type: proto.ColumnType_JSON, Description: ""},
			//{Name: "results", Type: proto.ColumnType_JSON, Description: ""},
			{Name: "metadata", Type: proto.ColumnType_JSON, Hydrate: scanTarget, Description: ""},
			{Name: "results", Type: proto.ColumnType_JSON, Hydrate: scanTarget, Description: ""},
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

type artifactRow struct {
	ArtifactType string
	ArtifactName string
}

func listTrivyTarget(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {

	//keyQuals := d.KeyColumnQuals
	images := []string{}
	paths := []string{}

	// type & name given - scan that exact combo
	// neither type or name given - scan from config
	// type given - limit scans to configs matching the type
	// name given - search

	/*
		var artifactType, artifactName string
		if keyQuals["artifact_type"] != nil {
			artifactType := keyQuals["artifact_type"].GetStringValue()
		}
		if keyQuals["artifact_name"] != nil {
			artifactName := keyQuals["artifact_name"].GetStringValue()
		}

		if keyQuals["artifact_name"] == nil {

			config := GetConfig(d.Connection)
			if &config != nil {

				if keyQuals["artifact_type"] == nil || artifactType == "image" {
					if config.Images != nil {
						images = append(images, config.Images...)
					}
				}

				if keyQuals["artifact_type"] == nil || artifactType == "fs" {
					if config.Paths != nil {
						paths = append(paths, config.Paths...)
					}
				}

			}

		} else {

			if keyQuals["artifact_type"] == nil {
			}


		}

	*/

	config := GetConfig(d.Connection)
	if &config != nil {
		if config.Images != nil {
			images = config.Images
		}
		if config.Paths != nil {
			paths = config.Paths
		}
	}

	plugin.Logger(ctx).Debug("trivy_target.listTrivyTarget", "config", config)
	plugin.Logger(ctx).Debug("trivy_target.listTrivyTarget", "images", images)
	plugin.Logger(ctx).Debug("trivy_target.listTrivyTarget", "paths", paths)

	for _, i := range images {
		d.StreamListItem(ctx, artifactRow{ArtifactType: "image", ArtifactName: i})
	}

	for _, i := range paths {
		d.StreamListItem(ctx, artifactRow{ArtifactType: "fs", ArtifactName: i})
	}

	/*
		for _, i := range images {
			imageResult, err := scanTarget(ctx, d, "image", i)
			if err == nil {
				d.StreamListItem(ctx, imageResult)
			}
		}

		for _, i := range paths {
			imageResult, err := scanTarget(ctx, d, "fs", i)
			if err == nil {
				d.StreamListItem(ctx, imageResult)
			}
		}
	*/

	return nil, nil
}

func listTrivyTargetWithScan(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {

	//keyQuals := d.KeyColumnQuals
	images := []string{}
	paths := []string{}

	// type & name given - scan that exact combo
	// neither type or name given - scan from config
	// type given - limit scans to configs matching the type
	// name given - search

	/*
		var artifactType, artifactName string
		if keyQuals["artifact_type"] != nil {
			artifactType := keyQuals["artifact_type"].GetStringValue()
		}
		if keyQuals["artifact_name"] != nil {
			artifactName := keyQuals["artifact_name"].GetStringValue()
		}

		if keyQuals["artifact_name"] == nil {

			config := GetConfig(d.Connection)
			if &config != nil {

				if keyQuals["artifact_type"] == nil || artifactType == "image" {
					if config.Images != nil {
						images = append(images, config.Images...)
					}
				}

				if keyQuals["artifact_type"] == nil || artifactType == "fs" {
					if config.Paths != nil {
						paths = append(paths, config.Paths...)
					}
				}

			}

		} else {

			if keyQuals["artifact_type"] == nil {
			}


		}

	*/

	config := GetConfig(d.Connection)
	if &config != nil {
		if config.Images != nil {
			images = config.Images
		}
		if config.Paths != nil {
			paths = config.Paths
		}
	}

	plugin.Logger(ctx).Debug("trivy_target.listTrivyTarget", "config", config)
	plugin.Logger(ctx).Debug("trivy_target.listTrivyTarget", "images", images)
	plugin.Logger(ctx).Debug("trivy_target.listTrivyTarget", "paths", paths)

	/*
		for _, i := range images {
			d.StreamListItem(ctx, artifactRow{ArtifactType: "image", ArtifactName: i})
		}

		for _, i := range paths {
			d.StreamListItem(ctx, artifactRow{ArtifactType: "fs", ArtifactName: i})
		}
	*/

	for _, i := range images {
		imageResult, err := scanTargetOld(ctx, d, "image", i)
		if err == nil {
			d.StreamListItem(ctx, imageResult)
		}
	}

	for _, i := range paths {
		imageResult, err := scanTargetOld(ctx, d, "fs", i)
		if err == nil {
			d.StreamListItem(ctx, imageResult)
		}
	}

	return nil, nil
}

func scanTarget(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	a := h.Item.(artifactRow)

	targetName := a.ArtifactName
	artifactType := a.ArtifactType

	plugin.Logger(ctx).Debug("trivy_target.scanTarget", "targetName", targetName)
	plugin.Logger(ctx).Debug("trivy_target.scanTarget", "artifactType", artifactType)

	cacheDir := GetConfigCacheDir(d.Connection)
	dbRepo := GetConfigDatabaseRepository(d.Connection)

	plugin.Logger(ctx).Debug("trivy_target.scanTarget", "cacheDir", cacheDir)
	plugin.Logger(ctx).Debug("trivy_target.scanTarget", "dbRepo", dbRepo)

	opt := artifact.Option{
		GlobalOption: option.GlobalOption{
			// Without context, Trivy crashes. So, mock their CLI context in a minimal way.
			Context: &cli.Context{
				Context: ctx,
			},
			// Use the cache dir as specified in the plugin config
			CacheDir: cacheDir,
		},
		// Target this specific artifact for scanning
		ArtifactOption: option.ArtifactOption{
			Target: targetName,
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
	plugin.Logger(ctx).Debug("trivy_target.scanTarget", "opt", opt)

	var report types.Report

	runner, err := artifact.NewRunner(opt)
	if err != nil {
		plugin.Logger(ctx).Error("trivy_target.scanTarget", "run_error", err, "opt", opt)
		return report, err
	}
	defer runner.Close(ctx)

	switch artifact.ArtifactType(artifactType) {
	case containerImageArtifact, imageArchiveArtifact:
		if report, err = runner.ScanImage(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_target.scanTarget", "artifactType", artifactType, "opt", opt, "scan_error", err)
			return report, nil //err
		}
	case filesystemArtifact:
		if report, err = runner.ScanFilesystem(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_target.scanTarget", "artifactType", artifactType, "opt", opt, "scan_error", err)
			return report, nil //err
		}
	case rootfsArtifact:
		if report, err = runner.ScanRootfs(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_target.scanTarget", "artifactType", artifactType, "opt", opt, "scan_error", err)
			return report, nil //err
		}
	case repositoryArtifact:
		if report, err = runner.ScanRepository(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_target.scanTarget", "artifactType", artifactType, "opt", opt, "scan_error", err)
			return report, nil //err
		}
	}

	return report, nil
}

func scanTargetOld(ctx context.Context, d *plugin.QueryData, artifactType artifact.ArtifactType, targetName string) (types.Report, error) {

	plugin.Logger(ctx).Debug("trivy_target.scanTarget", "targetName", targetName)
	plugin.Logger(ctx).Debug("trivy_target.scanTarget", "artifactType", artifactType)

	cacheDir := GetConfigCacheDir(d.Connection)
	dbRepo := GetConfigDatabaseRepository(d.Connection)

	plugin.Logger(ctx).Debug("trivy_target.scanTarget", "cacheDir", cacheDir)
	plugin.Logger(ctx).Debug("trivy_target.scanTarget", "dbRepo", dbRepo)

	opt := artifact.Option{
		GlobalOption: option.GlobalOption{
			// Without context, Trivy crashes. So, mock their CLI context in a minimal way.
			Context: &cli.Context{
				Context: ctx,
			},
			// Use the cache dir as specified in the plugin config
			CacheDir: cacheDir,
		},
		// Target this specific artifact for scanning
		ArtifactOption: option.ArtifactOption{
			Target: targetName,
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
	plugin.Logger(ctx).Debug("trivy_target.scanTarget", "opt", opt)

	var report types.Report

	runner, err := artifact.NewRunner(opt)
	if err != nil {
		plugin.Logger(ctx).Error("trivy_target.scanTarget", "run_error", err, "opt", opt)
		return report, err
	}
	defer runner.Close(ctx)

	switch artifactType {
	case containerImageArtifact, imageArchiveArtifact:
		if report, err = runner.ScanImage(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_target.scanTarget", "artifactType", artifactType, "opt", opt, "scan_error", err)
			return report, err
		}
	case filesystemArtifact:
		if report, err = runner.ScanFilesystem(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_target.scanTarget", "artifactType", artifactType, "opt", opt, "scan_error", err)
			return report, err
		}
	case rootfsArtifact:
		if report, err = runner.ScanRootfs(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_target.scanTarget", "artifactType", artifactType, "opt", opt, "scan_error", err)
			return report, err
		}
	case repositoryArtifact:
		if report, err = runner.ScanRepository(ctx, opt); err != nil {
			plugin.Logger(ctx).Error("trivy_target.scanTarget", "artifactType", artifactType, "opt", opt, "scan_error", err)
			return report, err
		}
	}

	return report, nil
}
