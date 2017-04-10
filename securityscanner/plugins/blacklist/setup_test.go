package blacklist

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	plugin := new(BlacklistPlugin)

	pluginGet, err := securityscanner.GetPlugin("Blacklist")
	assert.Nil(t, err)
	assert.Equal(t, plugin, pluginGet)
}
