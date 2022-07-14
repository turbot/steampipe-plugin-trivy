package trivy

import (
	"bytes"
	"context"
	"encoding/json"

	"go.etcd.io/bbolt"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"

	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/transform"
)

func tableTrivyAdvisory(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "trivy_advisory",
		Description: "Advisories detail the vulnerabilities affecting specific operating systems and packages.",
		List: &plugin.ListConfig{
			Hydrate: listTrivyAdvisory,
			KeyColumns: []*plugin.KeyColumn{
				{Name: "source", Require: plugin.Optional},
				{Name: "name", Require: plugin.Optional},
				{Name: "key", Require: plugin.Optional},
			},
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "source", Type: proto.ColumnType_STRING, Description: "Operating system or package the advisory is for, e.g. alpine 3.10."},
			{Name: "name", Type: proto.ColumnType_STRING, Description: "Name of the package with the vulnerability, e.g. ansible."},
			{Name: "key", Type: proto.ColumnType_STRING, Description: "Key referencing the vulnerability, e.g. CVE-2021-27506."},
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

	conn, err := connectDatabase(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("trivy_advisory.listTrivyAdvisory", "connection_error", err)
		return nil, err
	}

	keyQuals := d.KeyColumnQuals

	conn.View(func(tx *bbolt.Tx) error {
		err := tx.ForEach(func(sourceBytes []byte, b *bbolt.Bucket) error {

			source := string(sourceBytes)

			// Skip vulnerabilities and data sources, which are reported through separate tables
			switch source {
			case "vulnerability", "data-source", "Red Hat CPE":
				return nil
			}

			if keyQuals["source"] != nil {
				// If this source doesn't match the qual, then skip it
				if source != keyQuals["source"].GetStringValue() {
					return nil
				}
			}

			c := b.Cursor()

			namePrefix := []byte{}
			if keyQuals["name"] != nil {
				namePrefix = []byte(keyQuals["name"].GetStringValue())
			}

			for k, _ := c.Seek(namePrefix); k != nil && bytes.HasPrefix(k, namePrefix); k, _ = c.Next() {

				b2 := b.Bucket(k)
				c2 := b2.Cursor()

				keyPrefix := []byte{}
				if keyQuals["key"] != nil {
					keyPrefix = []byte(keyQuals["key"].GetStringValue())
				}

				for k2, v2 := c2.Seek(keyPrefix); k2 != nil && bytes.HasPrefix(k2, keyPrefix); k2, v2 = c2.Next() {

					var vuln dbTypes.Advisory
					err := json.Unmarshal(v2, &vuln)
					if err != nil {
						plugin.Logger(ctx).Warn("trivy_advisory.listTrivyAdvisory", "source", source, "name", string(k), "key", string(k2), "value", string(v2), "data_error", err)
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
