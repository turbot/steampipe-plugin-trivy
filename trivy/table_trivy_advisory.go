package trivy

import (
	"context"
	"encoding/json"

	//"github.com/aquasecurity/trivy/pkg/detector/library"

	//ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"go.etcd.io/bbolt"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"

	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

func tableTrivyAdvisory(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "trivy_advisory",
		Description: "Advisories.",
		List: &plugin.ListConfig{
			Hydrate: listTrivyAdvisory,
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "source", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "name", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "key", Type: proto.ColumnType_STRING, Description: ""},
			{Name: "vulnerability_id", Type: proto.ColumnType_STRING, Transform: transform.FromField("Value.VulnerabilityID").NullIfZero(), Description: "CVE-ID or vendor ID."},
			{Name: "vendor_ids", Type: proto.ColumnType_STRING, Transform: transform.FromField("Value.VendorIDs").NullIfZero(), Description: "RHSA-ID and DSA-ID."},
			{Name: "state", Type: proto.ColumnType_STRING, Transform: transform.FromField("Value.State").NullIfZero(), Description: "State of the advisory. Empty if fixed version is set. e.g. Will not fix and Affected."},
			{Name: "severity", Type: proto.ColumnType_JSON, Transform: transform.FromField("Value.Severity"), Description: ""},
			{Name: "fixed_version", Type: proto.ColumnType_STRING, Transform: transform.FromField("Value.FixedVersion").NullIfZero(), Description: "Version when the vulnerability is fixed."},
			{Name: "affected_version", Type: proto.ColumnType_STRING, Transform: transform.FromField("Value.AffectedVersion").NullIfZero(), Description: "Versions when the vulnerability is affected. Only for Arch Linux."},
			{Name: "vulnerable_versions", Type: proto.ColumnType_JSON, Transform: transform.FromField("Value.VulnerableVersions"), Description: "Versions that are vulnerable."},
			{Name: "patched_versions", Type: proto.ColumnType_JSON, Transform: transform.FromField("Value.PatchedVersions"), Description: "Versions that patch this vulnerability."},
			{Name: "unaffected_versions", Type: proto.ColumnType_JSON, Transform: transform.FromField("Value.UnaffectedVersions"), Description: "Versions that are not affected."},
		},
	}
}

type advisoryRow struct {
	Source string           `json:"source"`
	Name   string           `json:"name"`
	Key    string           `json:"key"`
	Value  dbTypes.Advisory `json:"value"`
}

func listTrivyAdvisory(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	/*

		appVersion := "0.0.0"
		cacheDir := "/Users/nathan/Library/Caches/trivy"
		dbRepo := "ghcr.io/aquasecurity/trivy-db"
		quiet := true
		insecure := false
		skipUpdate := false

		if err := operation.DownloadDB(appVersion, cacheDir, dbRepo, quiet, insecure, skipUpdate); err != nil {
			plugin.Logger(ctx).Error("trivy_advisory.listTrivyAdvisory", "db_error", err)
			return nil, err
		}

		if err := db.Init(cacheDir); err != nil {
			plugin.Logger(ctx).Error("trivy_advisory.listTrivyAdvisory", "db_error", err)
			return nil, err
		}

	*/

	db.Init("/Users/nathan/Library/Caches/trivy")
	dbc := db.Config{}

	conn := dbc.Connection()
	conn.View(func(tx *bbolt.Tx) error {
		err := tx.ForEach(func(sourceBytes []byte, b *bbolt.Bucket) error {

			source := string(sourceBytes)

			// Skip vulnerabilities and data sources, which are reported through separate tables
			switch source {
			case "vulnerability", "data-source", "Red Hat CPE":
				return nil
			}

			c := b.Cursor()

			for k, _ := c.First(); k != nil; k, _ = c.Next() {

				b2 := b.Bucket(k)
				c2 := b2.Cursor()
				for k2, v2 := c2.First(); k2 != nil; k2, v2 = c2.Next() {
					var vuln dbTypes.Advisory
					err := json.Unmarshal(v2, &vuln)
					if err != nil {
						plugin.Logger(ctx).Warn("trivy_advisory.listTrivyAdvisory", "source", source, "k", string(k), "k2", string(k2), "value", string(v2), "data_error", err)
					} else {
						d.StreamListItem(ctx, advisoryRow{Source: source, Name: string(k), Key: string(k2), Value: vuln})
					}
				}

			}

			return nil
		})
		return err
	})

	return nil, nil
}

/*

	var ecosystem types.Ecosystem = "npm"
	var prefix string = string(ecosystem) + "::"
	pkgName := "node-fetch"

	plugin.Logger(ctx).Warn("trivy_advisory.listTrivyAdvisory", "stage", "about to get advisories")

	items, err := dbc.GetAdvisories(prefix, vulnerability.NormalizePkgName(ecosystem, pkgName))
	if err != nil {
		plugin.Logger(ctx).Error("trivy_advisory.listTrivyAdvisory", "query_error", err)
		return nil, err
	}

	plugin.Logger(ctx).Warn("trivy_advisory.listTrivyAdvisory", "stage", "about to loop advisories")

	for _, adv := range items {
		plugin.Logger(ctx).Warn("trivy_advisory.listTrivyAdvisory", "adv", adv)
		d.StreamListItem(ctx, adv)
	}

	return nil, nil
}

*/

/*

func listTrivyAdvisory(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	driver, err := library.NewDriver("yarn")
	if err != nil {
		plugin.Logger(ctx).Error("trivy_advisory.listTrivyAdvisory", "driver_error", err)
		return nil, err
	}

	plugin.Logger(ctx).Warn("trivy_advisory.listTrivyAdvisory", "driver", driver)

	vulns, err := driver.DetectVulnerabilities("node-fetch", "2.6.1")
	if err != nil {
		plugin.Logger(ctx).Error("trivy_advisory.listTrivyAdvisory", "query_error", err)
		return nil, err
	}

	plugin.Logger(ctx).Warn("trivy_advisory.listTrivyAdvisory", "vulns", vulns)

	for _, i := range vulns {
		plugin.Logger(ctx).Warn("trivy_advisory.listTrivyAdvisory", "i", i)
		d.StreamListItem(ctx, i)
	}

	return nil, nil
}

*/
