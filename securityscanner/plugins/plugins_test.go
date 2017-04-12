package plugins

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
)

func TestAllPluginsRegistered(t *testing.T) {
	p := securityscanner.GetAllPlugins()
	assert.Equal(t, 9, len(p), "Incorrect number of plugins registered")
}
