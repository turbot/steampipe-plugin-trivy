package trivy

import (
	"context"
	"encoding/json"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"go.etcd.io/bbolt"

	"github.com/turbot/steampipe-plugin-sdk/v3/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
)

func tableTrivyDataSource(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "trivy_data_source",
		Description: "Data sources for advisory and vulnerability definitions.",
		List: &plugin.ListConfig{
			Hydrate: listTrivyDataSource,
		},
		Columns: []*plugin.Column{
			// Top columns
			{Name: "system", Type: proto.ColumnType_STRING, Description: "System the data source represents, e.g. alpine 3.11."},
			{Name: "id", Type: proto.ColumnType_STRING, Description: "Identifier of the data source, e.g. alpine."},
			{Name: "name", Type: proto.ColumnType_STRING, Description: "Name of the data source, e.g. Alpine Secdb."},
			{Name: "url", Type: proto.ColumnType_STRING, Description: "URL location of the data source."},
		},
	}
}

type dataSourceRow struct {
	System string `json:"system"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
}

func listTrivyDataSource(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	db.Init("/Users/nathan/Library/Caches/trivy")
	dbc := db.Config{}

	conn := dbc.Connection()
	conn.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("data-source"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var ds dbTypes.DataSource
			err := json.Unmarshal(v, &ds)
			if err != nil {
				continue
			}
			d.StreamListItem(ctx, dataSourceRow{System: string(k), ID: string(ds.ID), Name: ds.Name, URL: ds.URL})
		}
		return nil
	})

	return nil, nil
}
