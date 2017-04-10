package files

import (
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
)

var pluginName = "Sensitive files"
var pluginCode = "Files"

func TestFilesPlugin_Scan(t *testing.T) {
	plugin := new(FilesPlugin)
	plugin.SetArgs(&securityscanner.ScannerArgs{Domain: "www.google.pl", Protocol: "http"})

	val, err := plugin.Scan()
	assert.NoError(t, err)

	expectedKeys := []string{"git", "svn", "htaccess"}

	for _, k := range expectedKeys {
		assert.Contains(t, val, k)
		assert.NotEmpty(t, val[k], k)
	}
}

func TestFilesPlugin_Code(t *testing.T) {
	plugin := new(FilesPlugin)
	assert.Equal(t, plugin.Code(), pluginCode)
}

func TestFilesPlugin_Name(t *testing.T) {
	plugin := new(FilesPlugin)
	assert.Equal(t, plugin.Name(), pluginName)
}

func TestFilesPlugin_Info(t *testing.T) {
	plugin := new(FilesPlugin)
	val := plugin.Info()

	expectedKeys := []string{"git", "svn", "htaccess"}

	for _, k := range expectedKeys {
		assert.Contains(t, val, k)
	}
}
