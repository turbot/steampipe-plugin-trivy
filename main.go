package main

import (
	_ "github.com/aquasecurity/trivy-db/pkg/types"
	_ "github.com/aquasecurity/trivy/pkg/types"
	_ "github.com/turbot/steampipe-plugin-sdk/v5"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-trivy/trivy"
	_ "github.com/urfave/cli/v2"
	_ "go.etcd.io/bbolt"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{PluginFunc: trivy.Plugin})
}
