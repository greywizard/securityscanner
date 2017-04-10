package ports

import (
	"strconv"
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var pluginName = "Opened ports"
var pluginCode = "Ports"

func TestPortsPlugin_Scan(t *testing.T) {
	plugin := new(PortsPlugin)
	plugin.SetArgs(&securityscanner.ScannerArgs{Domain: "www.google.pl", Protocol: "http"})

	val, err := plugin.Scan()
	require.NoError(t, err)

	expectedKeys := portsToCheck

	for k, _ := range expectedKeys {
		intK := strconv.Itoa(k)
		require.Contains(t, val, intK)
		require.NotEmpty(t, val[intK], k)
	}
}

func TestPortsPlugin_Code(t *testing.T) {
	plugin := new(PortsPlugin)
	require.Equal(t, plugin.Code(), pluginCode)
}

func TestPortsPlugin_Name(t *testing.T) {
	plugin := new(PortsPlugin)
	require.Equal(t, plugin.Name(), pluginName)
}

func TestPortsPlugin_Info(t *testing.T) {
	plugin := new(PortsPlugin)
	val := plugin.Info()

	expectedKeys := portsToCheck

	for k, _ := range expectedKeys {
		assert.Contains(t, val, strconv.Itoa(k))
	}
}
