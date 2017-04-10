package pagespeed

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var pluginName = "Pagespeed"
var pluginCode = "Pagespeed"

func TestPagespeedPlugin_Configuration(t *testing.T) {
	apiKey := viper.GetString("pagespeed_api_key")
	assert.NotEmpty(t, apiKey, "pagespeed_api_key Not provided in configuration")
}

func TestPagespeedPlugin_Scan(t *testing.T) {
	plugin := new(PagespeedPlugin)
	plugin.SetArgs(&securityscanner.ScannerArgs{Domain: "www.google.pl", Protocol: "http"})

	val, err := plugin.Scan()
	require.NoError(t, err)

	expectedKeys := []string{"responseCode"}

	for _, k := range expectedKeys {
		require.Contains(t, val, k)
		require.NotEmpty(t, val[k], k)
	}
}

func TestPagespeedPlugin_Code(t *testing.T) {
	plugin := new(PagespeedPlugin)
	require.Equal(t, plugin.Code(), pluginCode)
}

func TestPagespeedPlugin_Name(t *testing.T) {
	plugin := new(PagespeedPlugin)
	require.Equal(t, plugin.Name(), pluginName)
}
