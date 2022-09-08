package main

import (
	"github.com/turbot/steampipe-plugin-sdk/v4/plugin"
	"github.com/turbot/steampipe-plugin-trivy/trivy"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{PluginFunc: trivy.Plugin})
}
