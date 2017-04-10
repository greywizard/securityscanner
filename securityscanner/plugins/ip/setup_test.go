package ip

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	plugin := new(IpPlugin)

	pluginGet, err := securityscanner.GetPlugin("IP")
	assert.Nil(t, err)
	assert.Equal(t, plugin, pluginGet)
}
