package blacklist

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var pluginName = "Blacklists"
var pluginCode = "Blacklist"

func TestBlacklistPlugin_Configuration(t *testing.T) {
	googleApiKey = viper.GetString("google_api_key")
	virustotalApiKey = viper.GetString("virustotal_api_key")

	assert.NotEmpty(t, googleApiKey, "google_api_key Not provided in configuration")
	assert.NotEmpty(t, virustotalApiKey, "virustotal_api_key Not provided in configuration")
}

func TestBlacklistPlugin_Scan(t *testing.T) {
	plugin := new(BlacklistPlugin)
	plugin.SetArgs(&securityscanner.ScannerArgs{Domain: "www.google.pl", Protocol: "http"})

	val, err := plugin.Scan()
	assert.NoError(t, err)

	expectedKeys := []string{"safebrowsing", "bitdefender", "eset", "kaspersky"}

	for _, k := range expectedKeys {
		assert.Contains(t, val, k)
		assert.NotEmpty(t, val[k], k)
	}
}

func TestBlacklistPlugin_Code(t *testing.T) {
	plugin := new(BlacklistPlugin)
	assert.Equal(t, plugin.Code(), pluginCode)
}

func TestBlacklistPlugin_Name(t *testing.T) {
	plugin := new(BlacklistPlugin)
	assert.Equal(t, plugin.Name(), pluginName)
}

func TestBlacklistPlugin_Info(t *testing.T) {
	plugin := new(BlacklistPlugin)
	val := plugin.Info()

	expectedKeys := []string{"safebrowsing", "bitdefender", "eset", "kaspersky"}

	for _, k := range expectedKeys {
		assert.Contains(t, val, k)
	}
}
