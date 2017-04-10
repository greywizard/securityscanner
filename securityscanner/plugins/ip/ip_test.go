package ip

import (
	"testing"

	"github.com/abh/geoip"
	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var pluginName = "IP"
var pluginCode = "IP"

func TestIpPlugin_Configuration(t *testing.T) {
	getPath := viper.GetString("geo_path")
	assert.NotEmpty(t, getPath, "geo_path Not provided in configuration")
}

func TestIpPlugin_CheckDatabase(t *testing.T) {
	var err error

	geoPath := viper.GetString("geo_path")

	_, err = geoip.Open(geoPath + "GeoIP.dat")
	require.NoError(t, err, "Geo IP Database not installed\nRun \"sh ./securityscanner/plugins/ip/geoip/get.sh\"")

	_, err = geoip.Open(geoPath + "GeoIPASNum.dat")
	require.NoError(t, err, "Geo IP Database not installed\nRun \"sh ./securityscanner/plugins/ip/geoip/get.sh\"")
}

func TestIpPlugin_Scan(t *testing.T) {
	plugin := new(IpPlugin)
	plugin.SetArgs(&securityscanner.ScannerArgs{Domain: "www.google.pl", Protocol: "http"})

	val, err := plugin.Scan()
	require.NoError(t, err)

	expectedKeys := []string{"ip", "country", "asn", "txt", "mx"}

	for _, k := range expectedKeys {
		assert.Contains(t, val, k)
	}

	expectedNotEmptyKeys := []string{"ip", "country", "asn"}

	for _, k := range expectedNotEmptyKeys {
		assert.NotEmpty(t, val[k], k)
	}
}

func TestIpPlugin_Code(t *testing.T) {
	plugin := new(IpPlugin)
	assert.Equal(t, plugin.Code(), pluginCode)
}

func TestIpPlugin_Name(t *testing.T) {
	plugin := new(IpPlugin)
	assert.Equal(t, plugin.Name(), pluginName)
}

func TestIpPlugin_Info(t *testing.T) {
	plugin := new(IpPlugin)
	plugin.SetArgs(&securityscanner.ScannerArgs{Domain: "www.google.pl", Protocol: "http"})

	val := plugin.Info()

	expectedKeys := []string{"ip", "country", "asn", "txt", "mx"}

	for _, k := range expectedKeys {
		assert.Contains(t, val, k)
	}
}
