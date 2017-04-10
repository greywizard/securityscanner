package headers

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
)

var pluginName = "HTTP Headers"
var pluginCode = "Headers"

func TestHeadersPlugin_Scan(t *testing.T) {
	plugin := new(HeadersPlugin)
	plugin.SetArgs(&securityscanner.ScannerArgs{Domain: "www.google.pl", Protocol: "http"})

	val, err := plugin.Scan()
	assert.NoError(t, err)

	expectedKeys := []string{"Server", "X-Powered-By", "X-AspNet-Version", "Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Xss-Protection", "X-Frame-Options"}

	for _, k := range expectedKeys {
		assert.Contains(t, val, k)
		assert.NotEmpty(t, val[k], k)
		assert.Contains(t, securityscanner.StatusColors, val[k])
	}
}

func TestHeadersPlugin_Code(t *testing.T) {
	plugin := new(HeadersPlugin)
	assert.Equal(t, plugin.Code(), pluginCode)
}

func TestHeadersPlugin_Name(t *testing.T) {
	plugin := new(HeadersPlugin)
	assert.Equal(t, plugin.Name(), pluginName)
}

func TestHeadersPlugin_Info(t *testing.T) {
	plugin := new(HeadersPlugin)
	val := plugin.Info()

	expectedKeys := []string{"Server", "X-Powered-By", "X-AspNet-Version", "Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Xss-Protection", "X-Frame-Options"}

	for _, k := range expectedKeys {
		assert.Contains(t, val, k)
	}
}
