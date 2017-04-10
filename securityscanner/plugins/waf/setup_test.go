package waf

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	plugin := new(WafPlugin)
	pluginGet, err := securityscanner.GetPlugin("Waf")
	assert.Nil(t, err)
	assert.Equal(t, plugin, pluginGet)
}
