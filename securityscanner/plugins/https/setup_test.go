package https

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	plugin := new(HttpsPlugin)
	pluginGet, err := securityscanner.GetPlugin("Https")
	assert.Nil(t, err)
	assert.Equal(t, plugin, pluginGet)
}
