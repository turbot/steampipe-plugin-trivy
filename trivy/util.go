package trivy

import (
	"context"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"go.etcd.io/bbolt"

	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
)

func connectDatabase(ctx context.Context, d *plugin.QueryData) (*bbolt.DB, error) {

	cacheKey := "trivy-database"
	if cachedData, ok := d.ConnectionManager.Cache.Get(cacheKey); ok {
		return cachedData.(*bbolt.DB), nil
	}

	// Default settings
	appVersion := "0.0.0"
	cacheDir := GetConfigCacheDir(d.Connection)
	dbRepo := GetConfigDatabaseRepository(d.Connection)
	quiet := true
	insecure := false
	skipUpdate := false

	// Download the latest copy of the database if it's not already there
	if err := operation.DownloadDB(appVersion, cacheDir, dbRepo, quiet, insecure, skipUpdate); err != nil {
		plugin.Logger(ctx).Error("trivy_advisory.listTrivyAdvisory", "db_error", err)
		return nil, err
	}

	// Initialize a connection to the database
	if err := db.Init(cacheDir); err != nil {
		plugin.Logger(ctx).Error("trivy_advisory.listTrivyAdvisory", "db_error", err)
		return nil, err
	}
	dbc := db.Config{}
	conn := dbc.Connection()

	// Save to cache
	d.ConnectionManager.Cache.Set(cacheKey, conn)

	return conn, nil
}
