package ports

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	plugin := new(PortsPlugin)
	pluginGet, err := securityscanner.GetPlugin("Ports")
	assert.Nil(t, err)
	assert.Equal(t, plugin, pluginGet)
}
