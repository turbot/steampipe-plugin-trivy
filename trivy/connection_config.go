package trivy

import (
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/schema"
)

type trivyConfig struct {
	Hostname *string `cty:"hostname"`
	APIKey   *string `cty:"api_key"`
	Username *string `cty:"username"`
	Password *string `cty:"password"`
	Timeout  *int    `cty:"timeout"`
}

var ConfigSchema = map[string]*schema.Attribute{
	"hostname": {
		Type: schema.TypeString,
	},
	"api_key": {
		Type: schema.TypeString,
	},
	"username": {
		Type: schema.TypeString,
	},
	"password": {
		Type: schema.TypeString,
	},
	"timeout": {
		Type: schema.TypeInt,
	},
}

func ConfigInstance() interface{} {
	return &trivyConfig{}
}

// GetConfig :: retrieve and cast connection config from query data
func GetConfig(connection *plugin.Connection) trivyConfig {
	if connection == nil || connection.Config == nil {
		return trivyConfig{}
	}
	config, _ := connection.Config.(trivyConfig)
	return config
}
