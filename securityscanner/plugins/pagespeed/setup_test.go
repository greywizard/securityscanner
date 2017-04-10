package pagespeed

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	plugin := new(PagespeedPlugin)
	pluginGet, err := securityscanner.GetPlugin("Pagespeed")
	assert.Nil(t, err)
	assert.Equal(t, plugin, pluginGet)
}
