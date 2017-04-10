package headers

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	plugin := new(HeadersPlugin)

	pluginGet, err := securityscanner.GetPlugin("Headers")
	assert.Nil(t, err)
	assert.Equal(t, plugin, pluginGet)
}
