package trivy

import (
	"os"
	"path"

	"github.com/turbot/steampipe-plugin-sdk/v3/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v3/plugin/schema"
)

type trivyConfig struct {
	CacheDir *string  `cty:"cache_dir"`
	Images   []string `cty:"images"`
	Paths    []string `cty:"paths"`
}

var ConfigSchema = map[string]*schema.Attribute{
	"cache_dir": {
		Type: schema.TypeString,
	},
	"images": {
		Type: schema.TypeList,
		Elem: &schema.Attribute{Type: schema.TypeString},
	},
	"paths": {
		Type: schema.TypeList,
		Elem: &schema.Attribute{Type: schema.TypeString},
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

// GetConfigCacheDir :: get cache directory from config, or return the default
func GetConfigCacheDir(connection *plugin.Connection) string {
	config := GetConfig(connection)
	cacheDir := path.Join(os.TempDir(), "steampipe-plugin-trivy")
	if config.CacheDir != nil {
		cacheDir = *config.CacheDir
	}
	return cacheDir
}

// GetConfigCacheDir :: get cache directory from config, or return the default
func GetConfigDatabaseRepository(connection *plugin.Connection) string {
	// No config for this setting yet, just return the default
	return "ghcr.io/aquasecurity/trivy-db"
}
