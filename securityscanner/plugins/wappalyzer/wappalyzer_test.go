package wappalyzer

import (
	"bytes"
	"io"
	"os/exec"
	"testing"

	"github.com/greywizard/securityscanner/securityscanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var pluginName = "Wappalyzer"
var pluginCode = "Wappalyzer"

func TestDockerImageExists(t *testing.T) {
	cmdW := exec.Command("docker", "--version")
	err := cmdW.Run()
	require.NoError(t, err, "Docker must be installed for this plugin")

	c1 := exec.Command("docker", "images")
	c2 := exec.Command("grep", "wappalyzer/grey_wizard")

	pr, pw := io.Pipe()
	c1.Stdout = pw
	c2.Stdin = pr

	var b2 bytes.Buffer
	c2.Stdout = &b2

	c1.Start()
	c2.Start()

	go func() {
		defer pw.Close()

		c1.Wait()
	}()
	c2.Wait()

	require.NotEmpty(t, b2.Len(), "Docker image \"wappalyzer/grey_wizard\" is not installed\nRun sh ./securityscanner/plugins/wappalyzer/Dockerfile/build.sh")
}

func TestWappalyzerPlugin_Scan(t *testing.T) {
	plugin := new(WappalyzerPlugin)
	plugin.SetArgs(&securityscanner.ScannerArgs{Domain: "www.google.pl", Protocol: "http"})

	_, err := plugin.Scan()
	require.NoError(t, err)
}

func TestWappalyzerPlugin_Code(t *testing.T) {
	plugin := new(WappalyzerPlugin)
	require.Equal(t, plugin.Code(), pluginCode)
}

func TestWappalyzerPlugin_Name(t *testing.T) {
	plugin := new(WappalyzerPlugin)
	require.Equal(t, plugin.Name(), pluginName)
}

func TestWappalyzerPlugin_Info(t *testing.T) {
	plugin := new(WappalyzerPlugin)
	val := plugin.Info()

	expectedKeys := []string{"Categories"}

	for _, k := range expectedKeys {
		assert.Contains(t, val, k)
	}
}
