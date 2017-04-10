package waf

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var pluginName = "Web Application Firewall (WAF)"
var pluginCode = "Waf"

func TestWafPlugin_Scan(t *testing.T) {
	plugin := new(WafPlugin)
	plugin.SetArgs(&securityscanner.ScannerArgs{Domain: "www.google.pl", Protocol: "http"})

	val, err := plugin.Scan()
	require.NoError(t, err)

	expectedKeys := []string{"provider", "xss", "traversal", "xss", "code", "sqli"}

	for _, k := range expectedKeys {
		require.Contains(t, val, k)
		require.NotEmpty(t, val[k], k)
		require.Contains(t, securityscanner.StatusColors, val[k])
	}
}

func TestWafPlugin_Code(t *testing.T) {
	plugin := new(WafPlugin)
	require.Equal(t, plugin.Code(), pluginCode)
}

func TestWafPlugin_Name(t *testing.T) {
	plugin := new(WafPlugin)
	require.Equal(t, plugin.Name(), pluginName)
}

func TestWafPlugin_Info(t *testing.T) {
	plugin := new(WafPlugin)
	val := plugin.Info()

	expectedKeys := []string{"provider", "xss", "traversal", "xss", "code", "sqli"}

	for _, k := range expectedKeys {
		assert.Contains(t, val, k)
	}
}
