package wappalyzer

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	plugin := new(WappalyzerPlugin)
	pluginGet, err := securityscanner.GetPlugin("Wappalyzer")
	assert.Nil(t, err)
	assert.Equal(t, plugin, pluginGet)
}
