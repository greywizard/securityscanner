package https

import (
	"testing"

	"os/exec"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/require"
)

var pluginName = "Https"
var pluginCode = "Https"

func TestNmapAvailable(t *testing.T) {
	cmdW := exec.Command("nmap", "-v")
	err := cmdW.Run()
	require.NoError(t, err, "Nmap must be installed for this plugin")
}

func TestHttpsPlugin_Scan(t *testing.T) {
	plugin := new(HttpsPlugin)
	plugin.SetArgs(&securityscanner.ScannerArgs{Domain: "www.google.pl", Protocol: "http"})

	val, err := plugin.Scan()
	require.NoError(t, err)

	expectedKeys := []string{"https", "poodle", "drown"} //TODO

	for _, k := range expectedKeys {
		require.Contains(t, val, k)
		require.NotEmpty(t, val[k], k)
		require.Contains(t, securityscanner.StatusColors, val[k])
	}
}

func TestHttpsPlugin_Code(t *testing.T) {
	plugin := new(HttpsPlugin)
	require.Equal(t, plugin.Code(), pluginCode)
}

func TestHttpsPlugin_Name(t *testing.T) {
	plugin := new(HttpsPlugin)
	require.Equal(t, plugin.Name(), pluginName)
}

func TestHttpsPlugin_Info(t *testing.T) {
	plugin := new(HttpsPlugin)
	val := plugin.Info()

	expectedKeys := []string{"https"} //TODO

	for _, k := range expectedKeys {
		require.Contains(t, val, k)
	}
}
