package pseudo

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	plugin := new(PseudoPlugin)

	pluginGet, err := securityscanner.GetPlugin("Pseudo")
	assert.Nil(t, err)
	assert.Equal(t, plugin, pluginGet)
}
