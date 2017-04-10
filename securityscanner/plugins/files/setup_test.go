package files

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
)

func TestSetup(t *testing.T) {
	plugin := new(FilesPlugin)
	pluginGet, err := securityscanner.GetPlugin("Files")

	assert.Nil(t, err)
	assert.Equal(t, plugin, pluginGet)
}
