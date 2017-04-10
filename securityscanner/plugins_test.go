package securityscanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type PluginTest struct {
	Plugin
}

func (s *PluginTest) Code() string {
	return s.Name()
}

func (s *PluginTest) Name() string {
	return "Pseudo"
}

func (s *PluginTest) Info() map[string]interface{} {
	return map[string]interface{}{
		"ok": "Show info that is ok",
	}
}

var testDomain = "www.google.pl"
var testProtocol = "http"

func TestRegisterPlugin(t *testing.T) {
	plugin := new(PluginTest)

	require.NotPanics(t, func() { RegisterPlugin("test", plugin) })

	p, err := GetPlugin("test")

	require.NoError(t, err)

	assert.Equal(t, plugin, p)

	DeregisterPlugin("test")

	_, err = GetPlugin("test")

	require.Error(t, err)
}

func TestRegisterPluginWithEmptyName(t *testing.T) {
	plugin := new(PluginTest)

	require.Panics(t, func() { RegisterPlugin("", plugin) })
}

func TestRegisterPluginDuplications(t *testing.T) {
	plugin := new(PluginTest)
	require.NotPanics(t, func() { RegisterPlugin("test", plugin) })
	require.Panics(t, func() { RegisterPlugin("test", plugin) })
	DeregisterPlugin("test")
}

func TestPlugin_SetArgs(t *testing.T) {
	plugin := new(PluginTest)
	plugin.SetArgs(&ScannerArgs{Domain: testDomain, Protocol: testProtocol})

	assert.Equal(t, plugin.Domain, testDomain)
	assert.Equal(t, plugin.Protocol, testProtocol)
}

func TestPlugin_Validate(t *testing.T) {
	plugin := new(PluginTest)
	assert.Panics(t, func() { plugin.Validate() })

	plugin.SetArgs(&ScannerArgs{Domain: testDomain, Protocol: testProtocol})
	assert.NotPanics(t, func() { plugin.Validate() })
}

func TestGetAllPlugins(t *testing.T) {
	plugin := new(PluginTest)

	require.NotPanics(t, func() { RegisterPlugin("test", plugin) })
	require.NotPanics(t, func() { RegisterPlugin("test2", plugin) })

	plugins := GetAllPlugins()

	assert.Equal(t, 2, len(plugins))
}
